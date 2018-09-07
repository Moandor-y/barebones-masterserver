﻿using System.Collections.Generic;
using System.Linq;
using Barebones.Networking;
using UnityEngine;

namespace Barebones.MasterServer
{
    public class MatchmakerModule : ServerModuleBehaviour
    {
        protected HashSet<IGamesProvider> GameProviders;

        public override void Initialize(IServer server)
        {
            base.Initialize(server);

            GameProviders = new HashSet<IGamesProvider>();

            // Add handlers
            server.SetHandler((short) MsfOpCodes.FindGames, HandleFindGames);
        }

        public void AddProvider(IGamesProvider provider)
        {
            GameProviders.Add(provider);
        }

        private void HandleFindGames(IIncommingMessage message)
        {
            var list = new List<GameInfoPacket>();

            var filters = new Dictionary<string, string>().FromBytes(message.AsBytes());

            foreach (var provider in GameProviders)
            {
                list.AddRange(provider.GetPublicGames(message.Peer, filters));
            }

            // Convert to generic list and serialize to bytes
            var bytes = list.Select(l => (ISerializablePacket)l).ToBytes();

            message.Respond(bytes, ResponseStatus.Success);
        }
    }
}