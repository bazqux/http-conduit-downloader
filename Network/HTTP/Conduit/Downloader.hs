{-# LANGUAGE OverloadedStrings, BangPatterns, RecordWildCards, ViewPatterns,
             DoAndIfThenElse, PatternGuards #-}
-- | HTTP downloader tailored for web-crawler needs.
--
--  * Handles all possible http-conduit exceptions and returns
--    human readable error messages.
--
--  * Handles some web server bugs (no persistent connections on HTTP/1.1,
--    returning @deflate@ data instead of @gzip@)
--
--  * Ignores invalid SSL sertificates.
--
--  * Receives data in 32k blocks internally to reduce memory fragmentation
--    on many parallel downloads.
--
--  * Download timeout.
--
--  * Total download size limit.
--
--  * Returns HTTP headers for subsequent redownloads
--    and handles @Not modified@ results.
--
--  * Can be used with external DNS resolver (hsdns-cache for example).
--
--  * Keep-alive connections pool (thanks to http-conduit).
--
--  Typical workflow in crawler:
--
--  @
--  withDnsCache $ \ c -> withDownloader $ \ d -> do
--  ... -- got URL from queue
--  ra <- resolveA c $ hostNameFromUrl url
--  case ra of
--      Left err -> ... -- uh oh, bad host
--      Right ha -> do
--          ... -- crawler politeness stuff (rate limits, domain queues)
--          dr <- download d url (Just ha) opts
--          case dr of
--              DROK dat redownloadOpts ->
--                  ... -- analyze data, save redownloadOpts for next download
--              DRRedirect .. -> ...
--              DRNotModified -> ...
--              DRError e -> ...
--  @
--
-- It's highly recommended to use
-- <http://hackage.haskell.org/package/hsdns-cache>
-- for DNS resolution since @getAddrInfo@ used in @http-conduit@ can be
-- buggy and ineffective when it needs to resolve many hosts per second for
-- a long time.
--
module Network.HTTP.Conduit.Downloader
    ( -- * Download operations
      urlGetContents, urlGetContentsPost
    , download, post, downloadG
    , DownloadResult(..), DownloadOptions

      -- * Downloader
    , DownloaderSettings(..)
    , Downloader, withDownloader, withDownloaderSettings, newDownloader

      -- * Utils
    , postRequest, sinkByteString
    ) where

import Control.Monad.Trans
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Internal as B
import Control.Monad
import qualified Control.Exception as E
import Data.Default
import Data.String
import Data.Char
import Data.Maybe
import Data.List
import Foreign
import qualified Network.Socket as NS
import qualified Network.TLS as TLS
import qualified Network.HTTP.Types as N
import qualified Network.HTTP.Conduit as C
import qualified Control.Monad.Trans.Resource as C
import qualified Data.Conduit as C
import System.Timeout.Lifted
import Codec.Compression.Zlib.Raw as Deflate
import Network.URI
-- import ADNS.Cache

-- | Result of 'download' operation.
data DownloadResult
    = DROK       B.ByteString DownloadOptions
      -- ^ Successful download with data and options for next download.
    | DRRedirect String
      -- ^ Redirect URL
    | DRError    String
      -- ^ Error
    | DRNotModified
      -- ^ HTTP 304 Not Modified
    deriving (Show, Read, Eq)

-- | @If-None-Match@ and/or @If-Modified-Since@ headers.
type DownloadOptions = [String]

-- | Settings used in downloader.
data DownloaderSettings
    = DownloaderSettings
      { dsUserAgent :: B.ByteString
        -- ^ User agent string. Default: @\"Mozilla\/5.0 (compatible; HttpConduitDownloader\/1.0; +http:\/\/hackage.haskell.org\/package\/http-conduit-downloader)\"@.
        --
        -- Be a good crawler. Provide your User-Agent please.
      , dsTimeout :: Int
        -- ^ Download timeout. Default: 30 seconds.
      , dsManagerSettings :: C.ManagerSettings
        -- ^ Conduit 'Manager' settings.
        -- Default: ManagerSettings with SSL certificate checks removed.
      , dsMaxDownloadSize :: Int
        -- ^ Download size limit. Default: 10MB.
      }
-- http://wiki.apache.org/nutch/OptimizingCrawls
-- use 10 seconds as default timeout (too small).

instance Default DownloaderSettings where
    def =
        DownloaderSettings
        { dsUserAgent = "Mozilla/5.0 (compatible; HttpConduitDownloader/1.0; +http://hackage.haskell.org/package/http-conduit-downloader)"
        , dsTimeout = 30
        , dsManagerSettings =
            C.def { C.managerCheckCerts =
                        \ _ _ _ -> return TLS.CertificateUsageAccept }
        , dsMaxDownloadSize = 10*1024*1024
        }

-- | Keeps http-conduit 'Manager' and 'DownloaderSettings'.
data Downloader
    = Downloader
      { manager :: C.Manager
      , settings :: DownloaderSettings
      }

-- | Create a 'Downloader' with settings.
newDownloader :: DownloaderSettings -> IO Downloader
newDownloader s = do
    m <- C.newManager $ dsManagerSettings s
    return $ Downloader m s

-- | Create a new 'Downloader', use it in the provided function,
-- and then release it.
withDownloader :: (Downloader -> IO a) -> IO a
withDownloader = withDownloaderSettings def

-- | Create a new 'Downloader' with provided settings,
-- use it in the provided function, and then release it.
withDownloaderSettings :: DownloaderSettings -> (Downloader -> IO a) -> IO a
withDownloaderSettings s f = C.runResourceT $ do
    (_, m) <- C.allocate (C.newManager $ dsManagerSettings s) C.closeManager
    liftIO $ f (Downloader m s)

parseUrl :: String -> Either C.HttpException (C.Request a)
parseUrl = C.parseUrl . takeWhile (/= '#')

-- | Perform download
download  ::    Downloader
             -> String -- ^ URL
             -> Maybe NS.HostAddress -- ^ Optional resolved 'HostAddress'
             -> DownloadOptions
             -> IO DownloadResult
download = downloadG return

-- | Perform HTTP POST.
post :: Downloader -> String -> Maybe NS.HostAddress -> B.ByteString
     -> IO DownloadResult
post d url ha dat =
    downloadG (return . postRequest dat) d url ha []

-- | Make HTTP POST request.
postRequest :: B.ByteString -> C.Request a -> C.Request b
postRequest dat rq =
    rq { C.method = N.methodPost
       , C.requestBody = C.RequestBodyBS dat }

-- | Generic version of 'download'
-- with ability to modify http-conduit 'Request'.
downloadG :: -- m ~ C.ResourceT IO
                (C.Request (C.ResourceT IO) -> C.ResourceT IO (C.Request (C.ResourceT IO)))
                -- ^ Function to modify 'Request'
                -- (e.g. sign or make 'postRequest')
             -> Downloader
             -> String -- ^ URL
             -> Maybe NS.HostAddress -- ^ Optional resolved 'HostAddress'
             -> DownloadOptions
             -> IO DownloadResult
downloadG f (Downloader {..}) url hostAddress opts =
  case parseUrl url of
    Left e -> httpExceptionToDR url e
    Right rq -> do
        let rq1 = rq { C.requestHeaders =
                               [("Accept", "*/*")
                               ,("User-Agent", dsUserAgent settings)
                               ]
                               ++ map toHeader opts
                               ++ C.requestHeaders rq
                     , C.redirectCount = 0
                     , C.responseTimeout = Nothing
                       -- We have timeout for connect and downloading
                       -- while http-conduit timeouts only when waits for
                       -- headers.
                     , C.hostAddress = hostAddress
                     }
        req <- C.runResourceT $ f rq1
        let dl firstTime = do
                r <- C.runResourceT (timeout (dsTimeout settings * 1000000) $ do
                    r <- C.http req manager
                    mbb <- C.responseBody r C.$$+-
                           sinkByteString (dsMaxDownloadSize settings)
--                    liftIO $ print ("sink", mbb)
                    case mbb of
                        Just b ->
                            let c = C.responseStatus r
                                h = C.responseHeaders r
                                d = tryDeflate h b in
                            return $ makeDownloadResultC url c h d
                        Nothing -> return $ DRError "Too much data")
                  `E.catch`
                    (fmap Just . httpExceptionToDR url)
                  `E.catch`
                    (return . Just . handshakeFailed)
                  `E.catch`
                    (return . Just . someException)
                case r of
                    Just (DRError e)
                        | ("EOF reached" `isSuffixOf` e ||
                           e == "Invalid HTTP status line:\n"
                          ) && firstTime ->
                        dl False
                        -- "EOF reached" or empty HTTP status line
                        -- can happen on servers that fails to
                        -- implement HTTP/1.1 persistent connections.
                        -- Try again
                        -- https://github.com/snoyberg/http-conduit/issues/89
                    _ ->
                        return $ fromMaybe (DRError "Timeout") r
        dl True
    where toHeader :: String -> N.Header
          toHeader h = let (a,b) = break (== ':') h in
                       (fromString a, fromString (tail b))
          handshakeFailed (TLS.HandshakeFailed tlsError) =
              DRError $ "SSL error:\n" ++ show tlsError
          someException :: E.SomeException -> DownloadResult
          someException e = case show e of
              "<<timeout>>" -> DRError "Timeout"
              s -> DRError s
          tryDeflate headers b
              | Just d <- lookup "Content-Encoding" headers
              , B.map toLower d == "deflate"
                  = B.concat $ BL.toChunks $ Deflate.decompress $
                    BL.fromChunks [b]
              | otherwise = b



httpExceptionToDR :: Monad m => String -> C.HttpException -> m DownloadResult
httpExceptionToDR url exn = return $ case exn of
    C.StatusCodeException c h _ -> -- trace "exception" $
                                 makeDownloadResultC url c h ""
    C.InvalidUrlException _ e -> DRError $ "Invalid URL: " ++ e
    C.TooManyRedirects _ -> DRError "Too many redirects"
    C.UnparseableRedirect _ -> DRError "Unparseable redirect"
    C.TooManyRetries -> DRError "Too many retries"
    C.HttpParserException e -> DRError $ "HTTP parser error: " ++ e
    C.HandshakeFailed -> DRError "Handshake failed"
    C.OverlongHeaders -> DRError "Overlong HTTP headers"
    C.ResponseTimeout -> DRError "Timeout"
    C.FailedConnectionException _host _port -> DRError "Connection failed"
    C.ExpectedBlankAfter100Continue -> DRError "Expected blank after 100 (Continue)"
    C.InvalidStatusLine l -> DRError $ "Invalid HTTP status line:\n" ++ B.unpack l
    C.InvalidHeader h -> DRError $ "Invalid HTTP header:\n" ++ B.unpack h
    C.InternalIOException e ->
        case show e of
            "<<timeout>>" -> DRError "Timeout"
            s -> DRError s
    C.ProxyConnectException {..} -> DRError "Can't connect to proxy"

bufSize :: Int
bufSize = 32 * 1024 - overhead -- Copied from Data.ByteString.Lazy.
    where overhead = 2 * sizeOf (undefined :: Int)

newBuf :: IO B.ByteString
newBuf = do
    fp <- B.mallocByteString bufSize
    return $ B.PS fp 0 0

addBs :: [B.ByteString] -> B.ByteString -> B.ByteString
      -> IO ([B.ByteString], B.ByteString)
addBs acc (B.PS bfp _ bl) (B.PS sfp offs sl) = do
    let cpSize = min (bufSize - bl) sl
        bl' = bl + cpSize
    withForeignPtr bfp $ \ dst -> withForeignPtr sfp $ \ src ->
        B.memcpy (dst `plusPtr` bl) (src `plusPtr` offs) (toEnum cpSize)
    if bl' == bufSize then do
        buf' <- newBuf
--        print ("filled", cpSize)
        addBs (B.PS bfp 0 bufSize : acc) buf'
              (B.PS sfp (offs + cpSize) (sl - cpSize))
    else do
--        print ("ok", cpSize, bl')
        return (acc, B.PS bfp 0 bl')

-- | Sink data using 32k buffers to reduce memory fragmentation.
-- Returns 'Nothing' if downloaded too much data.
sinkByteString :: MonadIO m => Int -> C.Sink B.ByteString m (Maybe B.ByteString)
sinkByteString limit = do
    buf <- liftIO $ newBuf
    go 0 [] buf
    where go len acc buf = do
              mbinp <- C.await
              case mbinp of
                  Just inp -> do
                      (acc', buf') <- liftIO $ addBs acc buf inp
--                      liftIO $ print (B.length inp)
                      let len' = len + B.length inp
                      if len' > limit then
                          return Nothing
                      else
                          go len' acc' buf'
                  Nothing -> do
--                      liftIO $ print ("len", length (buf:acc))
                      let d = B.concat $ reverse (buf:acc)
                      B.length d `seq` return $ Just d

makeDownloadResultC :: String -> N.Status -> N.ResponseHeaders
                    -> B.ByteString -> DownloadResult
makeDownloadResultC url c headers b = do
    if N.statusCode c == 304 then
        DRNotModified
    else if N.statusCode c `elem`
          [ 300 -- Multiple choices
          , 301 -- Moved permanently
          , 302 -- Found
          , 303 -- See other
          , 307 -- Temporary redirect
          ] then
        case lookup "location" headers of
            Just (B.unpack -> loc) ->
                redirect $
                    relUri (takeWhile (/= '#') $ dropWhile (== ' ') loc)
                    --  ^ Location can be relative and contain #fragment
            _ ->
                DRError $ "Redirect status, but no Location field\n"
                    ++ B.unpack (N.statusMessage c) ++ "\n"
                    ++ unlines (map show headers)
    else if N.statusCode c >= 300 then
        DRError $ "HTTP " ++ show (N.statusCode c) ++ " "
                    ++ B.unpack (N.statusMessage c)
    else
        DROK b (redownloadOpts headers)
    where redirect r
              | r == url = DRError $ "HTTP redirect to the same url?"
              | otherwise = DRRedirect r
          redownloadOpts [] = []
          redownloadOpts (("ETag", tag):xs) =
              ("If-None-Match: " ++ B.unpack tag) : redownloadOpts xs
          redownloadOpts (("Last-Modified", time):xs) =
              ("If-Modified-Since: " ++ B.unpack time) : redownloadOpts xs
          redownloadOpts (_:xs) = redownloadOpts xs
          relUri r =
              fromMaybe r $
              fmap (($ "") . uriToString id) $
              liftM2 relativeTo
                  (parseURIReference $ trim r)
                  (parseURI url)
          trim = reverse . dropWhile isSpace . reverse . dropWhile isSpace

-- | Download single URL with default 'DownloaderSettings'.
-- Fails if result is not 'DROK'.
urlGetContents :: String -> IO B.ByteString
urlGetContents url = withDownloader $ \ d -> do
    r <- download d url Nothing []
    case r of
        DROK c _ -> return c
        e -> fail $ "urlGetContents " ++ show url ++ ": " ++ show e

-- | Post data and download single URL with default 'DownloaderSettings'.
-- Fails if result is not 'DROK'.
urlGetContentsPost :: String -> B.ByteString -> IO B.ByteString
urlGetContentsPost url dat = withDownloader $ \ d -> do
    r <- post d url Nothing dat
    case r of
        DROK c _ -> return c
        e -> fail $ "urlGetContentsPost " ++ show url ++ ": " ++ show e
