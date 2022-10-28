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

        class CFileServer;
        class CFileHandler;

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileHandler ----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        typedef std::function<void (CFileHandler *Handler)> COnFileHandlerEvent;
        //--------------------------------------------------------------------------------------------------------------

        class CFileHandler: public CPollConnection {
        private:

            CFileServer *m_pModule;

            CString m_Session;

            bool m_Allow;

            CJSON m_Payload;

            COnFileHandlerEvent m_Handler;

            int AddToQueue();
            void RemoveFromQueue();

        protected:

            void SetAllow(bool Value) { m_Allow = Value; }

        public:

            CFileHandler(CFileServer *AModule, const CString &Data, COnFileHandlerEvent && Handler);

            ~CFileHandler() override;

            const CString &Session() const { return m_Session; }

            const CJSON &Payload() const { return m_Payload; }

            bool Allow() const { return m_Allow; };
            void Allow(bool Value) { SetAllow(Value); };

            bool Handler();

            void Close() override;

        };

        //--------------------------------------------------------------------------------------------------------------

        //-- CFileServer -----------------------------------------------------------------------------------------------

        //--------------------------------------------------------------------------------------------------------------

        class CFileServer: public CApostolModule {
        private:

            CString m_Session;

            CString m_Conf;
            CString m_Path;
            CString m_Agent;
            CString m_Host;

            CQueue m_Queue;
            CQueueManager m_QueueManager;

            CDateTime m_CheckDate;
            CDateTime m_AuthDate;

            size_t m_Progress;
            size_t m_MaxQueue;

            void InitListen();
            void CheckListen();

            void Authentication();
            void SignOut(const CString &Session);

            void UnloadQueue();

            void InitMethods() override;

            void DeleteHandler(CFileHandler *AHandler);

            static void QueryException(CPQPollQuery *APollQuery, const Delphi::Exception::Exception &E);

            static CString GetSession(CHTTPRequest *ARequest);

            static bool CheckAuthorizationData(CHTTPRequest *ARequest, CAuthorization &Authorization);
            static int CheckError(const CJSON &Json, CString &ErrorMessage);
            static CHTTPReply::CStatusType ErrorCodeToStatus(int ErrorCode);
            static void DeleteFile(const CString &FileName);

            CString VerifyToken(const CString &Token);

        protected:

            void DoError(const Delphi::Exception::Exception &E);

            void DoFile(CFileHandler *AHandler);
            void DoCopy(const CString &Copy, const CString &File);
            void DoCallBack(const CString &Session, const CString &Callback, const CString &Object, const CString &Name, const CString &Path, const CString &File);

            void DoGet(CHTTPServerConnection *AConnection) override;
            void DoPost(CHTTPServerConnection *AConnection);

            void DoGetFile(CHTTPServerConnection *AConnection, const CString &Session, const CString &Id, const CString &Path = "/", const CString &Name = CString());

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

            bool Enabled() override;

            bool CheckLocation(const CLocation &Location) override;
            bool CheckAuthorization(CHTTPServerConnection *AConnection, CString &Session, CAuthorization &Authorization);

            void IncProgress() { m_Progress++; }
            void DecProgress() { m_Progress--; }

            int AddToQueue(CFileHandler *AHandler);
            void InsertToQueue(int Index, CFileHandler *AHandler);
            void RemoveFromQueue(CFileHandler *AHandler);

            CQueue &Queue() { return m_Queue; }
            const CQueue &Queue() const { return m_Queue; }

            CPollManager *ptrQueueManager() { return &m_QueueManager; }

            CPollManager &QueueManager() { return m_QueueManager; }
            const CPollManager &QueueManager() const { return m_QueueManager; }

        };
    }
}

using namespace Apostol::Module;
}
#endif //APOSTOL_FILE_SERVER_HPP
