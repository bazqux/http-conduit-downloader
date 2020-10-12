{-# LANGUAGE OverloadedStrings, BangPatterns, RecordWildCards, ViewPatterns,
             DoAndIfThenElse, PatternGuards, ScopedTypeVariables,
             TupleSections #-}
{-# OPTIONS_GHC -fwarn-incomplete-patterns #-}
-- | HTTP downloader tailored for web-crawler needs.
--
--  * Handles all possible http-conduit exceptions and returns
--    human readable error messages.
--
--  * Handles some web server bugs (returning @deflate@ data instead of @gzip@,
--    invalid @gzip@ encoding).
--
--  * Uses OpenSSL instead of @tls@ package (since @tls@ doesn't handle all sites).
--
--  * Ignores invalid SSL sertificates.
--
--  * Receives data in 32k chunks internally to reduce memory fragmentation
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
--          ... -- crawler politeness stuff (rate limits, queues)
--          dr <- download d url (Just ha) opts
--          case dr of
--              DROK dat redownloadOptions ->
--                  ... -- analyze data, save redownloadOpts for next download
--              DRRedirect .. -> ...
--              DRNotModified -> ...
--              DRError e -> ...
--  @
--
-- It's highly recommended to use
-- <http://hackage.haskell.org/package/concurrent-dns-cache>
-- (preferably with single resolver pointing to locally running BIND)
-- for DNS resolution since @getAddrInfo@ used in @http-conduit@ can be
-- buggy and ineffective when it needs to resolve many hosts per second for
-- a long time.
--
module Network.HTTP.Conduit.Downloader
    ( -- * Download operations
      urlGetContents, urlGetContentsPost
    , download, post, downloadG, rawDownload
    , DownloadResult(..), RawDownloadResult(..), DownloadOptions

      -- * Downloader
    , DownloaderSettings(..)
    , Downloader, withDownloader, withDownloaderSettings, newDownloader

      -- * Utils
    , postRequest, sinkByteString
    ) where

import Control.Monad.Trans
import qualified Data.Text as T
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Internal as B
import Control.Monad
import qualified Control.Exception as E
import Data.Default as C
import Data.String
import Data.Char
import Data.Maybe
import Data.List
import Foreign
import qualified Network.Socket as NS
-- import qualified Network.TLS as TLS
-- import qualified Network.Connection as NC
import qualified OpenSSL as SSL
import qualified OpenSSL.Session as SSL
import qualified Network.HTTP.Types as N
import qualified Network.HTTP.Conduit as C
import Network.HTTP.Client.Internal (makeConnection, Connection)
import qualified Control.Monad.Trans.Resource as C
import qualified Data.Conduit as C
import System.Timeout
import Codec.Compression.Zlib.Raw as Deflate
import Network.URI
-- import ADNS.Cache
import Data.Time.Format
import Data.Time.Clock
import Data.Time.Clock.POSIX

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

-- | Result of 'rawDownload' operation.
data RawDownloadResult
    = RawDownloadResult
      { rdrStatus :: N.Status
      , rdrHttpVersion :: N.HttpVersion
      , rdrHeaders :: N.ResponseHeaders
      , rdrBody :: B.ByteString
      , rdrCookieJar :: C.CookieJar
      }
    deriving Show

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
        -- ^ Download size limit in bytes. Default: 10MB.
      }
-- http://wiki.apache.org/nutch/OptimizingCrawls
-- use 10 seconds as default timeout (too small).

instance Default DownloaderSettings where
    def =
        DownloaderSettings
        { dsUserAgent = "Mozilla/5.0 (compatible; HttpConduitDownloader/1.0; +http://hackage.haskell.org/package/http-conduit-downloader)"
        , dsTimeout = 30
        , dsManagerSettings =
            C.tlsManagerSettings
            { C.managerTlsConnection =
              -- IO (Maybe HostAddress -> String -> Int -> IO Connection)
              getOpenSSLConnection
            }
--             (C.mkManagerSettings tls Nothing)
--             { C.managerTlsConnection =
--               -- IO (Maybe HostAddress -> String -> Int -> IO Connection)
--               getTlsConnection (Just tls)
--             }
--             C.def { C.managerCheckCerts =
--                         \ _ _ _ -> return TLS.CertificateUsageAccept }
        , dsMaxDownloadSize = 10*1024*1024
        }
--        where tls = NC.TLSSettingsSimple True False False

-- tls package doesn't handle some sites:
-- https://github.com/vincenthz/hs-tls/issues/53
-- using OpenSSL instead
getOpenSSLConnection :: IO (Maybe NS.HostAddress -> String -> Int
                            -> IO Connection)
getOpenSSLConnection = do
    ctx <- SSL.context
--     SSL.contextSetCiphers ctx "DEFAULT"
--     SSL.contextSetVerificationMode ctx SSL.VerifyNone
--     SSL.contextAddOption ctx SSL.SSL_OP_NO_SSLv3
--     SSL.contextAddOption ctx SSL.SSL_OP_ALL
    return $ \ mbha host port -> do
        sock <- case mbha of
            Nothing -> openSocketByName host port
            Just ha -> openSocket ha port
        ssl <- SSL.connection ctx sock
        SSL.setTlsextHostName ssl host
        SSL.connect ssl
        makeConnection
            (SSL.read ssl bufSize
             `E.catch`
             \ (_ :: SSL.ConnectionAbruptlyTerminated) -> return ""
            )
            (SSL.write ssl)
            -- Closing an SSL connection gracefully involves writing/reading
            -- on the socket.  But when this is called the socket might be
            -- already closed, and we get a @ResourceVanished@.
            (NS.close sock `E.catch` \(_ :: E.IOException) -> return ())
--            ((SSL.shutdown ssl SSL.Bidirectional >> return ()) `E.catch` \(_ :: E.IOException) -> return ())
-- segmentation fault in GHCi with SSL.shutdown / tryShutdown SSL.Unidirectional
-- hang with SSL.Bidirectional

-- Network.HTTP.Client.TLS.getTlsConnection with ability to use HostAddress
-- since Network.Connection.connectTo uses Network.connectTo that uses
-- getHostByName (passed HostAddress is ignored)
-- getTlsConnection :: Maybe NC.TLSSettings
-- --                 -> Maybe NC.SockSettings
--                  -> IO (Maybe NS.HostAddress -> String -> Int -> IO Connection)
-- getTlsConnection tls = do
--     context <- NC.initConnectionContext
--     return $ \ mbha host port -> do
--         cf <- case mbha of
--             Nothing -> return $ NC.connectTo context
--             Just ha -> do
--                 sock <- openSocket ha port
--                 handle <- NS.socketToHandle sock ReadWriteMode
--                 return $ NC.connectFromHandle context handle
--         conn <- cf $ NC.ConnectionParams
--             { NC.connectionHostname = host
--             , NC.connectionPort = fromIntegral port
--             , NC.connectionUseSecure = tls
--             , NC.connectionUseSocks = Nothing -- sock
--             }
--         convertConnection conn
--   where
--     convertConnection conn = makeConnection
--         (NC.connectionGetChunk conn)
--         (NC.connectionPut conn)
--         -- Closing an SSL connection gracefully involves writing/reading
--         -- on the socket.  But when this is called the socket might be
--         -- already closed, and we get a @ResourceVanished@.
--         (NC.connectionClose conn `E.catch` \(_ :: E.IOException) -> return ())

-- slightly modified Network.HTTP.Client.Connection.openSocketConnection
openSocket :: NS.HostAddress
           -> Int -- ^ port
           -> IO NS.Socket
openSocket ha port =
    openSocket' $
        NS.AddrInfo
        { NS.addrFlags = []
        , NS.addrFamily = NS.AF_INET
        , NS.addrSocketType = NS.Stream
        , NS.addrProtocol = 6 -- tcp
        , NS.addrAddress = NS.SockAddrInet (toEnum port) ha
        , NS.addrCanonName = Nothing
        }
openSocket' :: NS.AddrInfo -> IO NS.Socket
openSocket' addr = do
    E.bracketOnError
        (NS.socket (NS.addrFamily addr) (NS.addrSocketType addr)
                   (NS.addrProtocol addr))
        (NS.close)
        (\sock -> do
            NS.setSocketOption sock NS.NoDelay 1
            NS.connect sock (NS.addrAddress addr)
            return sock)

openSocketByName :: Show a => NS.HostName -> a -> IO NS.Socket
openSocketByName host port = do
    let hints = NS.defaultHints
                { NS.addrFlags = []-- [NS.AI_ADDRCONFIG, NS.AI_NUMERICSERV]
                , NS.addrFamily = NS.AF_INET
                , NS.addrSocketType = NS.Stream
                , NS.addrProtocol = 6 -- tcp
                }
    (addrInfo:_) <- NS.getAddrInfo (Just hints) (Just host) (Just $ show port)
    openSocket' addrInfo

-- | Keeps http-conduit 'Manager' and 'DownloaderSettings'.
data Downloader
    = Downloader
      { manager :: C.Manager
      , settings :: DownloaderSettings
      }

-- | Create a 'Downloader' with settings.
newDownloader :: DownloaderSettings -> IO Downloader
newDownloader s = do
    SSL.withOpenSSL $ return () -- init in case it wasn't initialized yet
    m <- C.newManager $ dsManagerSettings s
    return $ Downloader m s

-- | Create a new 'Downloader', use it in the provided function,
-- and then release it.
withDownloader :: (Downloader -> IO a) -> IO a
withDownloader = withDownloaderSettings def

-- | Create a new 'Downloader' with provided settings,
-- use it in the provided function, and then release it.
withDownloaderSettings :: DownloaderSettings -> (Downloader -> IO a) -> IO a
withDownloaderSettings s f = f =<< newDownloader s

parseUrl :: String -> Either E.SomeException C.Request
parseUrl = C.parseRequest . takeWhile (/= '#')

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
postRequest :: B.ByteString -> C.Request -> C.Request
postRequest dat rq =
    rq { C.method = N.methodPost
       , C.requestBody = C.RequestBodyBS dat }

-- | Generic version of 'download'
-- with ability to modify http-conduit 'Request'.
downloadG :: -- m ~ C.ResourceT IO
                (C.Request -> C.ResourceT IO C.Request)
                -- ^ Function to modify 'Request'
                -- (e.g. sign or make 'postRequest')
             -> Downloader
             -> String -- ^ URL
             -> Maybe NS.HostAddress -- ^ Optional resolved 'HostAddress'
             -> DownloadOptions
             -> IO (DownloadResult)
downloadG f d u h o = fmap fst $ rawDownload f d u h o

-- | Even more generic version of 'download', which returns 'RawDownloadResult'.
-- 'RawDownloadResult' is optional since it can not be determined on timeouts
-- and connection errors.
rawDownload :: -- m ~ C.ResourceT IO
                (C.Request -> C.ResourceT IO C.Request)
                -- ^ Function to modify 'Request'
                -- (e.g. sign or make 'postRequest')
             -> Downloader
             -> String -- ^ URL
             -> Maybe NS.HostAddress -- ^ Optional resolved 'HostAddress'
             -> DownloadOptions
             -> IO (DownloadResult, Maybe RawDownloadResult)
rawDownload f (Downloader {..}) url hostAddress opts =
  case parseUrl url of
    Left e ->
        fmap (, Nothing) $
        maybe (return $ DRError $ show e) (httpExceptionToDR url)
              (E.fromException e)
    Right rq -> do
        let dl req firstTime = do
                r <- (timeout (dsTimeout settings * 1000000) $ C.runResourceT $ do
                    r <- C.http req manager
                    let s = C.responseStatus r
                        h = C.responseHeaders r
                        rdr d =
                            RawDownloadResult
                            { rdrStatus = s
                            , rdrHttpVersion = C.responseVersion r
                            , rdrHeaders = h
                            , rdrBody = d
                            , rdrCookieJar = C.responseCookieJar r
                            }
                        readLen = B.foldl' (\ a d -> a * 10 + ord d - ord '0') 0
                    mbb <- case lookup "Content-Length" h of
                        Just l
                            | B.all (\ c -> c >= '0' && c <= '9') l
                              && not (B.null l)
                              && readLen l > dsMaxDownloadSize settings
                            -> do
                               -- liftIO $ putStrLn "Content-Length too large"
                               return Nothing
                               -- no reason to download body
                        _ ->
                            C.sealConduitT (C.responseBody r) C.$$+-
                                sinkByteString (dsMaxDownloadSize settings)
--                    liftIO $ print ("sink", mbb)
                    case mbb of
                        Just b -> do
                            let d = tryDeflate h b
                            curTime <- liftIO $ getCurrentTime
                            return
                                (makeDownloadResultC curTime url s h d
                                , Just $ rdr d)
                        Nothing ->
                            return (DRError "Too much data", Just $ rdr ""))
                  `E.catch`
                    (fmap (Just . (, Nothing)) . httpExceptionToDR url)
--                   `E.catch`
--                     (return . Just . handshakeFailed)
                  `E.catch`
                    (return . (Just . (, Nothing)) . someException)
                case r of
                    Just (DRError e, _)
                        | ("EOF reached" `isSuffixOf` e
                           || e == "Invalid HTTP status line:\n"
                           || e == "Incomplete headers"
                          ) && firstTime ->
                            dl req False
                        -- "EOF reached" or empty HTTP status line
                        -- can happen on servers that fails to
                        -- implement HTTP/1.1 persistent connections.
                        -- Try again
                        -- https://github.com/snoyberg/http-conduit/issues/89
                        -- Fixed in
                        -- https://github.com/snoyberg/http-conduit/issues/117
                        | "ZlibException" `isPrefixOf` e && firstTime ->
                            -- some sites return junk instead of gzip data.
                            -- retrying without compression
                            dl (disableCompression req) False
                    _ ->
                        return $ fromMaybe (DRError "Timeout", Nothing) r
            disableCompression req =
                req { C.requestHeaders =
                          ("Accept-Encoding", "") : C.requestHeaders req }
            rq1 = rq { C.requestHeaders =
                               [("Accept", "*/*")
                               ,("User-Agent", dsUserAgent settings)
                               ]
                               ++ map toHeader opts
                               ++ C.requestHeaders rq
                     , C.redirectCount = 0
                     , C.responseTimeout = C.responseTimeoutNone
                       -- We have timeout for connect and downloading
                       -- while http-conduit timeouts only when waits for
                       -- headers.
                     , C.hostAddress = hostAddress
                     , C.checkResponse = \ _ _ -> return ()
                     }
        req <- C.runResourceT $ f rq1
        dl req True
    where toHeader :: String -> N.Header
          toHeader h = let (a,b) = break (== ':') h in
                       (fromString a, fromString (tail b))
          someException :: E.SomeException -> DownloadResult
          someException e = case show e of
              "<<timeout>>" -> DRError "Timeout"
              s -> DRError s
          tryDeflate headers b
              | Just d <- lookup "Content-Encoding" headers
              , B.map toLower d == "deflate"
                  = BL.toStrict $ Deflate.decompress $ BL.fromStrict b
              | otherwise = b

httpExceptionToDR :: Monad m => String -> C.HttpException -> m DownloadResult
httpExceptionToDR url exn = return $ case exn of
    C.HttpExceptionRequest _ ec -> httpExceptionContentToDR url ec
    C.InvalidUrlException _ e
        | e == "Invalid URL" -> DRError e
        | otherwise -> DRError $ "Invalid URL: " ++ e

httpExceptionContentToDR :: String -> C.HttpExceptionContent -> DownloadResult
httpExceptionContentToDR url ec = case ec of
    C.StatusCodeException r b ->
      makeDownloadResultC (posixSecondsToUTCTime 0) url
      (C.responseStatus r) (C.responseHeaders r) b
    C.TooManyRedirects _ -> DRError "Too many redirects"
    C.OverlongHeaders -> DRError "Overlong HTTP headers"
    C.ResponseTimeout -> DRError "Timeout"
    C.ConnectionTimeout -> DRError "Connection timeout"
    C.ConnectionFailure e -> DRError $ "Connection failed: " ++ show e
    C.InvalidStatusLine l -> DRError $ "Invalid HTTP status line:\n" ++ B.unpack l
    C.InvalidHeader h -> DRError $ "Invalid HTTP header:\n" ++ B.unpack h
    C.InvalidRequestHeader h -> DRError $ "Invalid HTTP request header:\n" ++ B.unpack h
    C.InternalException e ->
        case show e of
            "<<timeout>>" -> DRError "Timeout"
            s -> DRError s
    C.ProxyConnectException _ _ _ -> DRError "Can't connect to proxy"
    C.NoResponseDataReceived -> DRError "No response data received"
    C.TlsNotSupported -> DRError "TLS not supported"
    C.WrongRequestBodyStreamSize e a ->
        DRError $ "The request body provided did not match the expected size "
        ++ ea e a
    C.ResponseBodyTooShort e a -> DRError $ "Response body too short " ++ ea e a
    C.InvalidChunkHeaders -> DRError "Invalid chunk headers"
    C.IncompleteHeaders -> DRError "Incomplete headers"
    C.InvalidDestinationHost _ -> DRError "Invalid destination host"
    C.HttpZlibException e -> DRError $ show e
    C.InvalidProxyEnvironmentVariable n v ->
        DRError $ "Invalid proxy environment variable "
        ++ show n ++ "=" ++ show v
    C.InvalidProxySettings s -> DRError $ "Invalid proxy settings:\n" ++ T.unpack s
    C.ConnectionClosed -> DRError "Connection closed"
    where ea expected actual =
              "(expected " ++ show expected ++ " bytes, actual is "
              ++ show actual ++ " bytes)"

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
sinkByteString :: MonadIO m => Int -> C.ConduitT B.ByteString C.Void m (Maybe B.ByteString)
sinkByteString limit = do
    buf <- liftIO $ newBuf
    go 0 [] buf
    where go len acc buf = do
              mbinp <- C.await
              case mbinp of
                  Just inp -> do
                      (acc', buf') <- liftIO $ addBs acc buf inp
                      let len' = len + B.length inp
                      if len' > limit then
                          return Nothing
                      else
                          go len' acc' buf'
                  Nothing -> do
                      return $ Just $ B.concat $ reverse (buf:acc)

makeDownloadResultC :: UTCTime -> String -> N.Status -> N.ResponseHeaders
                    -> B.ByteString -> DownloadResult
makeDownloadResultC curTime url c headers b = do
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
        DROK b (redownloadOpts [] headers)
    where redirect r
--              | r == url = DRError $ "HTTP redirect to the same url?"
              | otherwise = DRRedirect r
          redownloadOpts acc [] = reverse acc
          redownloadOpts _ (("Pragma", B.map toLower -> tag) : _)
              | "no-cache" `B.isInfixOf` tag = []
          redownloadOpts _ (("Cache-Control", B.map toLower -> tag) : _)
              | any (`B.isInfixOf` tag)
                ["no-cache", "no-store", "must-revalidate", "max-age=0"] = []
          redownloadOpts acc (("Expires", time):xs)
              | ts <- B.unpack time
              , Just t <- parseHttpTime ts
              , t > curTime =
                   redownloadOpts acc xs
              | otherwise = [] -- expires is non-valid or in the past
          redownloadOpts acc (("ETag", tag):xs) =
              redownloadOpts (("If-None-Match: " ++ B.unpack tag) : acc) xs
          redownloadOpts acc (("Last-Modified", time):xs)
              | ts <- B.unpack time
              , Just t <- parseHttpTime ts
              , t <= curTime = -- use only valid timestamps
              redownloadOpts (("If-Modified-Since: " ++ B.unpack time) : acc) xs
          redownloadOpts acc (_:xs) = redownloadOpts acc xs
          fixNonAscii =
              escapeURIString
                  (\ x -> ord x <= 0x7f && x `notElem` (" []{}|\"" :: String)) .
              trimString
          relUri (fixNonAscii -> r) =
              fromMaybe r $
              fmap (($ "") . uriToString id) $
              liftM2 relativeTo
                  (parseURIReference r)
                  (parseURI $ fixNonAscii url)

-- fmap utcTimeToPOSIXSeconds $

tryParseTime :: [String] -> String -> Maybe UTCTime
tryParseTime formats string =
    foldr mplus Nothing $
    map (\ fmt -> parseTimeM True defaultTimeLocale fmt (trimString string))
        formats

trimString :: String -> String
trimString = reverse . dropWhile isSpace . reverse . dropWhile isSpace

parseHttpTime :: String -> Maybe UTCTime
parseHttpTime =
    tryParseTime
    ["%a, %e %b %Y %k:%M:%S %Z" -- Sun, 06 Nov 1994 08:49:37 GMT
    ,"%A, %e-%b-%y %k:%M:%S %Z" -- Sunday, 06-Nov-94 08:49:37 GMT
    ,"%a %b %e %k:%M:%S %Y"     -- Sun Nov  6 08:49:37 1994
    ]

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
