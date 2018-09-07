using System;
using Barebones.Networking;

namespace Barebones.MasterServer
{
    public class MsfServer : MsfBaseClient
    {
        public MsfSpawnersServer Spawners { get; private set; }

        public MsfDbAccessorFactory DbAccessors;

        public MsfAuthServer Auth { get; private set; }

        public MsfProfilesServer Profiles { get; private set; }

        public MsfServer(IClientSocket connection) : base(connection)
        {
            DbAccessors = new MsfDbAccessorFactory();
            Spawners = new MsfSpawnersServer(connection);
            Auth = new MsfAuthServer(connection);
            Profiles = new MsfProfilesServer(connection);
        }
    }
}