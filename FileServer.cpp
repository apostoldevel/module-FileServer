/*++

Program name:

  Apostol Web Service

Module Name:

  FileServer.cpp

Notices:

  Module: File Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

//----------------------------------------------------------------------------------------------------------------------

#include "Core.hpp"
#include "FileServer.hpp"
//----------------------------------------------------------------------------------------------------------------------

#include "jwt.h"
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Module {

        CString squeeze(const CString &data, const char litter = '\n') {
            CString result;
            size_t pos = 0;
            TCHAR ch = data.at(pos++);

            while (ch) {
                if (ch != litter)
                    result.Append(ch);
                ch = data.at(pos++);
            }

            return result;
        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer ---------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        CFileServer::CFileServer(CModuleProcess *AProcess) : CApostolModule(AProcess, "file server", "module/FileServer") {
            m_Headers.Add("Authorization");
            m_Headers.Add("Session");
            m_Headers.Add("Secret");
            m_Headers.Add("Nonce");
            m_Headers.Add("Signature");

            m_FixedDate = Now();

            CFileServer::InitMethods();
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::InitMethods() {
#if defined(_GLIBCXX_RELEASE) && (_GLIBCXX_RELEASE >= 9)
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoGet(Connection); }));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoPost(Connection); }));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , [this](auto && Connection) { DoOptions(Connection); }));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, [this](auto && Connection) { MethodNotAllowed(Connection); }));
#else
            m_pMethods->AddObject(_T("GET")    , (CObject *) new CMethodHandler(true , std::bind(&CFileServer::DoGet, this, _1)));
            m_pMethods->AddObject(_T("POST")   , (CObject *) new CMethodHandler(true , std::bind(&CFileServer::DoPost, this, _1)));
            m_pMethods->AddObject(_T("OPTIONS"), (CObject *) new CMethodHandler(true , std::bind(&CFileServer::DoOptions, this, _1)));
            m_pMethods->AddObject(_T("HEAD")   , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PUT")    , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("DELETE") , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("TRACE")  , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("PATCH")  , (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
            m_pMethods->AddObject(_T("CONNECT"), (CObject *) new CMethodHandler(false, std::bind(&CFileServer::MethodNotAllowed, this, _1)));
#endif
        }
        //--------------------------------------------------------------------------------------------------------------

        CHTTPReply::CStatusType CFileServer::ErrorCodeToStatus(int ErrorCode) {
            CHTTPReply::CStatusType status = CHTTPReply::ok;

            if (ErrorCode != 0) {
                switch (ErrorCode) {
                    case 401:
                        status = CHTTPReply::unauthorized;
                        break;

                    case 403:
                        status = CHTTPReply::forbidden;
                        break;

                    case 404:
                        status = CHTTPReply::not_found;
                        break;

                    case 500:
                        status = CHTTPReply::internal_server_error;
                        break;

                    default:
                        status = CHTTPReply::bad_request;
                        break;
                }
            }

            return status;
        }
        //--------------------------------------------------------------------------------------------------------------

        int CFileServer::CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError) {
            int errorCode = 0;

            if (Json.HasOwnProperty(_T("error"))) {
                const auto& error = Json[_T("error")];

                if (error.HasOwnProperty(_T("code"))) {
                    errorCode = error[_T("code")].AsInteger();
                } else {
                    errorCode = 40000;
                }

                if (error.HasOwnProperty(_T("message"))) {
                    ErrorMessage = error[_T("message")].AsString();
                } else {
                    ErrorMessage = _T("Invalid request.");
                }

                if (RaiseIfError)
                    throw EDBError(ErrorMessage.c_str());

                if (errorCode >= 10000)
                    errorCode = errorCode / 100;

                if (errorCode < 0)
                    errorCode = 400;
            }

            return errorCode;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CFileServer::GetSession(CHTTPRequest *ARequest) {
            const auto& headerSession = ARequest->Headers.Values(_T("Session"));
            const auto& cookieSession = ARequest->Cookies.Values(_T("SID"));

            return headerSession.IsEmpty() ? cookieSession : headerSession;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckSession(CHTTPRequest *ARequest, CString &Session) {
            const auto& caSession = GetSession(ARequest);

            if (caSession.Length() != 40)
                return false;

            Session = caSession;

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        CString CFileServer::VerifyToken(const CString &Token) {

            const auto& GetSecret = [](const CProvider &Provider, const CString &Application) {
                const auto &Secret = Provider.Secret(Application);
                if (Secret.IsEmpty())
                    throw ExceptionFrm("Not found Secret for \"%s:%s\"", Provider.Name().c_str(), Application.c_str());
                return Secret;
            };

            auto decoded = jwt::decode(Token);
            const auto& aud = CString(decoded.get_audience());

            CString Application;

            const auto& Providers = Server().Providers();

            const auto Index = OAuth2::Helper::ProviderByClientId(Providers, aud, Application);
            if (Index == -1)
                throw COAuth2Error(_T("Not found provider by Client ID."));

            const auto& Provider = Providers[Index].Value();

            const auto& iss = CString(decoded.get_issuer());

            CStringList Issuers;
            Provider.GetIssuers(Application, Issuers);
            if (Issuers[iss].IsEmpty())
                throw jwt::token_verification_exception("Token doesn't contain the required issuer.");

            const auto& alg = decoded.get_algorithm();
            const auto& ch = alg.substr(0, 2);

            const auto& Secret = GetSecret(Provider, Application);

            if (ch == "HS") {
                if (alg == "HS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs256{Secret});
                    verifier.verify(decoded);

                    return Token; // if algorithm HS256
                } else if (alg == "HS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs384{Secret});
                    verifier.verify(decoded);
                } else if (alg == "HS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::hs512{Secret});
                    verifier.verify(decoded);
                }
            } else if (ch == "RS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "RS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs256{key});
                    verifier.verify(decoded);
                } else if (alg == "RS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs384{key});
                    verifier.verify(decoded);
                } else if (alg == "RS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "ES") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "ES256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es256{key});
                    verifier.verify(decoded);
                } else if (alg == "ES384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es384{key});
                    verifier.verify(decoded);
                } else if (alg == "ES512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::es512{key});
                    verifier.verify(decoded);
                }
            } else if (ch == "PS") {

                const auto& kid = decoded.get_key_id();
                const auto& key = OAuth2::Helper::GetPublicKey(Providers, kid);

                if (alg == "PS256") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps256{key});
                    verifier.verify(decoded);
                } else if (alg == "PS384") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps384{key});
                    verifier.verify(decoded);
                } else if (alg == "PS512") {
                    auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::ps512{key});
                    verifier.verify(decoded);
                }
            }

            const auto& Result = CCleanToken(R"({"alg":"HS256","typ":"JWT"})", decoded.get_payload(), true);

            return Result.Sign(jwt::algorithm::hs256{Secret});
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization) {

            const auto &caHeaders = ARequest->Headers;
            const auto &caAuthorization = caHeaders.Values(_T("Authorization"));

            if (caAuthorization.IsEmpty()) {

                const auto &headerSession = caHeaders.Values(_T("Session"));
                const auto &headerSecret = caHeaders.Values(_T("Secret"));

                Authorization.Username = headerSession;
                Authorization.Password = headerSecret;

                if (Authorization.Username.IsEmpty() || Authorization.Password.IsEmpty())
                    return false;

                Authorization.Schema = CAuthorization::asBasic;
                Authorization.Type = CAuthorization::atSession;

            } else {
                Authorization << caAuthorization;
            }

            return true;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization) {

            auto pRequest = AConnection->Request();

            try {
                if (CheckAuthorizationData(pRequest, Authorization)) {
                    if (Authorization.Schema == CAuthorization::asBearer) {
                        Authorization.Token = VerifyToken(Authorization.Token);
                        return true;
                    }
                }

                if (Authorization.Schema == CAuthorization::asBasic)
                    AConnection->Data().Values("Authorization", "Basic");

                ReplyError(AConnection, CHTTPReply::unauthorized, "Unauthorized.");
            } catch (jwt::token_expired_exception &e) {
                ReplyError(AConnection, CHTTPReply::forbidden, e.what());
            } catch (jwt::token_verification_exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (CAuthorizationError &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            } catch (std::exception &e) {
                ReplyError(AConnection, CHTTPReply::bad_request, e.what());
            }

            return false;
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload) {

        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::ReplyQuery(CHTTPServerConnection *AConnection, CPQResult *AResult) {

            auto pRequest = AConnection->Request();
            auto pReply = AConnection->Reply();

            pReply->ContentType = CHTTPReply::json;

            CString errorMessage;

            CStringList ResultObject;
            CStringList ResultFormat;

            ResultObject.Add("true");
            ResultObject.Add("false");

            ResultFormat.Add("object");
            ResultFormat.Add("array");
            ResultFormat.Add("null");

            const auto &result_object = pRequest->Params[_T("result_object")];
            const auto &result_format = pRequest->Params[_T("result_format")];

            if (!result_object.IsEmpty() && ResultObject.IndexOfName(result_object) == -1) {
                ReplyError(AConnection, CHTTPReply::bad_request, CString().Format("Invalid result_object: %s", result_object.c_str()));
                return;
            }

            if (!result_format.IsEmpty() && ResultFormat.IndexOfName(result_format) == -1) {
                ReplyError(AConnection, CHTTPReply::bad_request, CString().Format("Invalid result_format: %s", result_format.c_str()));
                return;
            }

            const auto &patch = AConnection->Data()["path"].Lower();
            const auto bDataArray = patch.Find(_T("/list")) != CString::npos;

            CString Format(result_format);
            if (Format.IsEmpty() && bDataArray)
                Format = "array";

            CHTTPReply::CStatusType status = CHTTPReply::ok;

            try {
                if (AResult->nTuples() == 1) {
                    const CJSON Payload(AResult->GetValue(0, 0));
                    status = ErrorCodeToStatus(CheckError(Payload, errorMessage));
                    if (status == CHTTPReply::ok) {
                        AfterQuery(AConnection, patch, Payload);
                    }
                }

                PQResultToJson(AResult, pReply->Content, Format, result_object == "true" ? "result" : CString());

                if (status == CHTTPReply::ok && !pReply->CacheFile.IsEmpty()) {
                    pReply->Content.SaveToFile(pReply->CacheFile.c_str());
                }
            } catch (Delphi::Exception::Exception &E) {
                errorMessage = E.what();
                status = CHTTPReply::bad_request;
                Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            }

            if (status == CHTTPReply::ok) {
                AConnection->SendReply(status, nullptr, true);
            } else {
                ReplyError(AConnection, status, errorMessage);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Agent, const CString &Host,
                COnPQPollQueryExecutedEvent &&OnExecuted, COnPQPollQueryExceptionEvent &&OnException) {

            CStringList SQL;

            const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

            SQL.Add(CString()
                .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                .Format("SELECT * FROM daemon.unauthorized_fetch(%s, %s, %s::jsonb, %s, %s);",
                                     PQQuoteLiteral(Method).c_str(),
                                     PQQuoteLiteral(Path).c_str(),
                                     caPayload.c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str()
            ));

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "false");
            AConnection->Data().Values("signature", "false");

            try {
                ExecSQL(SQL, AConnection, std::move(OnExecuted), std::move(OnException));
            } catch (Delphi::Exception::Exception &E) {
                AConnection->SendStockReply(CHTTPReply::service_unavailable);
                Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Method, const CString &Path, const CString &Payload, const CString &Agent, const CString &Host,
                COnPQPollQueryExecutedEvent &&OnExecuted, COnPQPollQueryExceptionEvent &&OnException) {

            CStringList SQL;

            if (Authorization.Schema == CAuthorization::asBearer) {

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                    .MaxFormatSize(256 + Authorization.Token.Size() + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                    .Format("SELECT * FROM daemon.fetch(%s, %s, %s, %s::jsonb, %s, %s);",
                                         PQQuoteLiteral(Authorization.Token).c_str(),
                                         PQQuoteLiteral(Method).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         caPayload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else if (Authorization.Schema == CAuthorization::asBasic) {

                const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

                SQL.Add(CString()
                    .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Agent.Size())
                    .Format("SELECT * FROM daemon.%s_fetch(%s, %s, %s, %s, %s::jsonb, %s, %s);",
                                         Authorization.Type == CAuthorization::atSession ? "session" : "authorized",
                                         PQQuoteLiteral(Authorization.Username).c_str(),
                                         PQQuoteLiteral(Authorization.Password).c_str(),
                                         PQQuoteLiteral(Method).c_str(),
                                         PQQuoteLiteral(Path).c_str(),
                                         caPayload.c_str(),
                                         PQQuoteLiteral(Agent).c_str(),
                                         PQQuoteLiteral(Host).c_str()
                ));

            } else {

                return UnauthorizedFetch(AConnection, Method, Path, Payload, Agent, Host, std::move(OnExecuted), std::move(OnException));

            }

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "false");

            try {
                ExecSQL(SQL, AConnection, std::move(OnExecuted), std::move(OnException));
            } catch (Delphi::Exception::Exception &E) {
                AConnection->SendStockReply(CHTTPReply::service_unavailable);
                Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::SignedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Session, const CString &Nonce, const CString &Signature,
                const CString &Agent, const CString &Host, long int ReceiveWindow,
                COnPQPollQueryExecutedEvent &&OnExecuted, COnPQPollQueryExceptionEvent &&OnException) {

            CStringList SQL;

            const auto &caPayload = Payload.IsEmpty() ? "null" : PQQuoteLiteral(Payload);

            SQL.Add(CString()
                .MaxFormatSize(256 + Method.Size() + Path.Size() + caPayload.Size() + Session.Size() + Nonce.Size() + Signature.Size() + Agent.Size())
                .Format("SELECT * FROM daemon.signed_fetch(%s, %s, %s::json, %s, %s, %s, %s, %s, INTERVAL '%d milliseconds');",
                                     PQQuoteLiteral(Method).c_str(),
                                     PQQuoteLiteral(Path).c_str(),
                                     caPayload.c_str(),
                                     PQQuoteLiteral(Session).c_str(),
                                     PQQuoteLiteral(Nonce).c_str(),
                                     PQQuoteLiteral(Signature).c_str(),
                                     PQQuoteLiteral(Agent).c_str(),
                                     PQQuoteLiteral(Host).c_str(),
                                     ReceiveWindow
            ));

            AConnection->Data().Values("method", Method);
            AConnection->Data().Values("path", Path);
            AConnection->Data().Values("authorized", "true");
            AConnection->Data().Values("signature", "true");

            try {
                ExecSQL(SQL, AConnection, std::move(OnExecuted), std::move(OnException));
            } catch (Delphi::Exception::Exception &E) {
                AConnection->SendStockReply(CHTTPReply::service_unavailable);
                Log()->Error(APP_LOG_ERR, 0, "%s", E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                COnPQPollQueryExecutedEvent &&OnExecuted, COnPQPollQueryExceptionEvent &&OnException) {

            auto pRequest = AConnection->Request();

            const auto& caContentType = pRequest->Headers.Values(_T("Content-Type")).Lower();
            const auto bContentJson = (caContentType.Find(_T("application/json")) != CString::npos);

            CJSON Json;
            if (!bContentJson) {
                ContentToJson(pRequest, Json);
            }

            const auto& caPayload = bContentJson ? pRequest->Content : Json.ToString();
            const auto& caSignature = pRequest->Headers.Values(_T("Signature"));

            const auto& caAgent = GetUserAgent(AConnection);
            const auto& caHost = GetRealIP(AConnection);

            try {
                if (caSignature.IsEmpty()) {
                    CAuthorization Authorization;
                    if (CheckAuthorization(AConnection, Authorization)) {
                        AuthorizedFetch(AConnection, Authorization, Method, Path, caPayload, caAgent, caHost, std::move(OnExecuted), std::move(OnException));
                    }
                } else {
                    const auto& caSession = GetSession(pRequest);
                    const auto& caNonce = pRequest->Headers.Values(_T("Nonce"));

                    long int receiveWindow = 5000;
                    const auto& caReceiveWindow = pRequest->Params[_T("receive_window")];
                    if (!caReceiveWindow.IsEmpty())
                        receiveWindow = StrToIntDef(caReceiveWindow.c_str(), receiveWindow);

                    SignedFetch(AConnection, Method, Path, caPayload, caSession, caNonce, caSignature, caAgent, caHost, receiveWindow, std::move(OnExecuted), std::move(OnException));
                }
            } catch (Delphi::Exception::Exception &E) {
                ReplyError(AConnection, CHTTPReply::bad_request, E.what());
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoFile(CHTTPServerConnection *AConnection, const CString &Method, const CString &Id,
                const CString &Path, const CString &Name) {

            auto OnExecuted = [](CPQPollQuery *APollQuery) {

                auto pResult = APollQuery->Results(0);

                if (pResult->ExecStatus() != PGRES_TUPLES_OK) {
                    QueryException(APollQuery, Delphi::Exception::EDBError("DBError: %s", pResult->GetErrorMessage()));
                    return;
                }

                auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());

                if (pConnection != nullptr && !pConnection->ClosedGracefully()) {

                    auto pReply = pConnection->Reply();

                    CString errorMessage;
                    CHTTPReply::CStatusType status;

                    try {
                        if (pResult->nTuples() == 1) {
                            const CJSON Payload(pResult->GetValue(0, 0));
                            status = ErrorCodeToStatus(CheckError(Payload, errorMessage));

                            if (status != CHTTPReply::ok) {
                                ReplyError(pConnection, status, errorMessage);
                                return;
                            }

                            const auto &caFile = Payload.Object();

                            const auto &name = caFile["name"].AsString();
                            const auto &path = caFile["path"].AsString();
                            const auto &date = caFile["loaded"].AsString();
                            const auto &data = caFile["data"].IsNull() ? CString() : caFile["data"].AsString();

                            CString sFileExt;
                            TCHAR szBuffer[MAX_BUFFER_SIZE + 1] = {0};

                            sFileExt = ExtractFileExt(szBuffer, name.c_str());

                            auto sModified = StrWebTime(FileAge(date.c_str()), szBuffer, sizeof(szBuffer));
                            if (sModified != nullptr) {
                                pReply->AddHeader(_T("Last-Modified"), sModified);
                            }

                            if (data.IsEmpty()) {
                                pReply->Content.Clear();
                                pConnection->SendStockReply(CHTTPReply::no_content, true);
                                return;
                            }

                            pReply->Content = base64_decode(squeeze(data));
                            pConnection->SendReply(CHTTPReply::ok, Mapping::ExtToType(sFileExt.c_str()), true);

                            return;
                        }

                        pConnection->SendStockReply(CHTTPReply::not_found, true);
                    } catch (Delphi::Exception::Exception &E) {
                        ReplyError(pConnection, CHTTPReply::bad_request, E.what());
                    } catch (std::exception &e) {
                        ReplyError(pConnection, CHTTPReply::internal_server_error, e.what());
                    }
                }
            };

            CString sName(CHTTPServer::URLDecode(Name));

            if (path_separator(sName.back())) {
                sName += APOSTOL_INDEX_FILE;
            }

            auto pRequest = AConnection->Request();

            pRequest->Params.Clear();
            pRequest->Params.AddPair("id", Id);
            pRequest->Params.AddPair("name", Name);
            pRequest->Params.AddPair("path", Path);

            DoFetch(AConnection, "GET", "/api/v1/object/file/get", OnExecuted);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());
            ReplyError(pConnection, CHTTPReply::internal_server_error, E.what());
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoPostgresQueryExecuted(CPQPollQuery *APollQuery) {

            auto pResult = APollQuery->Results(0);

            if (pResult->ExecStatus() != PGRES_TUPLES_OK) {
                QueryException(APollQuery, Delphi::Exception::EDBError("DBError: %s", pResult->GetErrorMessage()));
                return;
            }

            auto pConnection = dynamic_cast<CHTTPServerConnection *> (APollQuery->Binding());

            if (pConnection != nullptr && !pConnection->ClosedGracefully()) {
                ReplyQuery(pConnection, pResult);
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) {
            QueryException(APollQuery, E);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoGet(CHTTPServerConnection *AConnection) {

            auto pRequest = AConnection->Request();

            CString sPath(pRequest->Location.pathname);

            // Request path must be absolute and not contain "..".
            if (sPath.empty() || sPath.front() != '/' || sPath.find(_T("..")) != CString::npos) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            CStringList slRouts;
            CString sName;

            SplitColumns(sPath, slRouts, '/');

            sPath = "~/";

            if (slRouts.Count() < 2) {
                AConnection->SendStockReply(CHTTPReply::not_found);
                return;
            } if (slRouts.Count() == 2) {
                sName << APOSTOL_INDEX_FILE;
            } else {
                for (int i = 2; i < slRouts.Count() - 1; ++i) {
                    sPath << slRouts[i];
                    sPath << "/";
                }
                sName << slRouts.Last();
            }

            DoFile(AConnection, "GET", slRouts[1], sPath, sName);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::DoPost(CHTTPServerConnection *AConnection) {

            auto pRequest = AConnection->Request();

            CString sPath(pRequest->Location.pathname);

            // Request path must be absolute and not contain "..".
            if (sPath.empty() || sPath.front() != '/' || sPath.find(_T("..")) != CString::npos) {
                AConnection->SendStockReply(CHTTPReply::bad_request);
                return;
            }

            DoFetch(AConnection, "POST", sPath);
        }
        //--------------------------------------------------------------------------------------------------------------

        void CFileServer::Heartbeat(CDateTime DateTime) {
            if ((DateTime >= m_FixedDate)) {
                m_FixedDate = DateTime + (CDateTime) 30 / MinsPerDay; // 30 min
            }
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::Enabled() {
            if (m_ModuleStatus == msUnknown)
                m_ModuleStatus = Config()->IniFile().ReadBool(SectionName(), "enable", true) ? msEnabled : msDisabled;
            return m_ModuleStatus == msEnabled;
        }
        //--------------------------------------------------------------------------------------------------------------

        bool CFileServer::CheckLocation(const CLocation &Location) {
            return Location.pathname.SubString(0, 6) == _T("/file/");
        }
        //--------------------------------------------------------------------------------------------------------------
    }
}
}