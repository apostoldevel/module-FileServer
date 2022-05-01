/*++

Program name:

  Apostol Web Service

Module Name:

  FileServer.hpp

Notices:

  Module: File Server

Author:

  Copyright (c) Prepodobny Alen

  mailto: alienufo@inbox.ru
  mailto: ufocomp@gmail.com

--*/

#ifndef APOSTOL_FILE_SERVER_HPP
#define APOSTOL_FILE_SERVER_HPP
//----------------------------------------------------------------------------------------------------------------------

extern "C++" {

namespace Apostol {

    namespace Module {

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServer: public CApostolModule {
        private:

            CDateTime m_FixedDate;

            void InitMethods() override;

            static void AfterQuery(CHTTPServerConnection *AConnection, const CString &Path, const CJSON &Payload);

            static void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static bool CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization);

            static void ReplyQuery(CHTTPServerConnection *AConnection, CPQResult *AResult);

            static int CheckError(const CJSON &Json, CString &ErrorMessage, bool RaiseIfError = false);
            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);

        protected:

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoFile(CHTTPServerConnection *AConnection, const CString &Method, const CString &Id, const CString &Path = "~/", const CString &Name = CString());
            void DoFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                COnPQPollQueryExecutedEvent && OnExecuted = nullptr, COnPQPollQueryExceptionEvent && OnException = nullptr);

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CFileServer(CModuleProcess *AProcess);

            ~CFileServer() override = default;

            static class CFileServer *CreateModule(CModuleProcess *AProcess) {
                return new CFileServer(AProcess);
            }

            CString VerifyToken(const CString &Token);

            bool CheckAuthorization(CHTTPServerConnection *AConnection, CAuthorization &Authorization);

            void UnauthorizedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Agent, const CString &Host,
                COnPQPollQueryExecutedEvent && OnExecuted = nullptr, COnPQPollQueryExceptionEvent && OnException = nullptr);

            void AuthorizedFetch(CHTTPServerConnection *AConnection, const CAuthorization &Authorization,
                const CString &Method, const CString &Path, const CString &Payload, const CString &Agent, const CString &Host,
                COnPQPollQueryExecutedEvent && OnExecuted = nullptr, COnPQPollQueryExceptionEvent && OnException = nullptr);

            void SignedFetch(CHTTPServerConnection *AConnection, const CString &Method, const CString &Path,
                const CString &Payload, const CString &Session, const CString &Nonce, const CString &Signature,
                const CString &Agent, const CString &Host, long int ReceiveWindow = 5000,
                COnPQPollQueryExecutedEvent && OnExecuted = nullptr, COnPQPollQueryExceptionEvent && OnException = nullptr);

            static CString GetSession(CHTTPRequest *ARequest);
            static bool CheckSession(CHTTPRequest *ARequest, CString &Session);

            void Heartbeat(CDateTime DateTime) override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_FILE_SERVER_HPP
