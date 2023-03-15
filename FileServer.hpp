/*++

Program name:

  Apostol CRM

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

        //-- CFileHandler ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileHandler: public CQueueHandler {
        private:

            CString m_Session;
            CString m_FileId;

            CJSON m_Payload;

        public:

            CFileHandler(CQueueCollection *ACollection, const CString &Data, COnQueueHandlerEvent && Handler);

            const CString &Session() const { return m_Session; }
            const CString &FileId() const { return m_FileId; }

            const CJSON &Payload() const { return m_Payload; }

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServer: public CQueueCollection, public CApostolModule {
        private:

            CString m_Session;

            CString m_Conf;
            CString m_Path;
            CString m_Agent;
            CString m_Host;

            CDateTime m_CheckDate;
            CDateTime m_AuthDate;

            void InitMethods() override;

            void InitListen();
            void CheckListen();

            void Authentication();
            void SignOut(const CString &Session);

            static void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static CString GetSession(const CHTTPRequest &Request);

            static bool CheckAuthorizationData(const CHTTPRequest &Request, CAuthorization &Authorization);
            static int CheckError(const CJSON &Json, CString &ErrorMessage);
            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);
            static void DeleteFile(const CString &FileName);

            CString VerifyToken(const CString &Token);

        protected:

            void DoError(const Delphi::Exception::Exception &E);

            void DoFile(CQueueHandler *AHandler);

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoGetFile(CHTTPServerConnection *AConnection, const CString &Session, const CString &Path, const CString &Name);

            void DoPostgresNotify(CPQConnection *AConnection, PGnotify *ANotify) override;

            void DoPostgresQueryExecuted(CPQPollQuery *APollQuery) override;
            void DoPostgresQueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E) override;

        public:

            explicit CFileServer(CModuleProcess *AProcess);

            ~CFileServer() override = default;

            static class CFileServer *CreateModule(CModuleProcess *AProcess) {
                return new CFileServer(AProcess);
            }

            void Initialization(CModuleProcess *AProcess) override;

            CPQPollQuery *GetQuery(CPollConnection *AConnection) override;

            void Heartbeat(CDateTime Now) override;

            void UnloadQueue() override;

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;
            bool CheckAuthorization(CHTTPServerConnection *AConnection, CString &Session, CAuthorization &Authorization);

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_FILE_SERVER_HPP
