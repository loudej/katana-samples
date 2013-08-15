using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Infrastructure;

namespace ServerApp
{
    public class SingleUseInMemoryNonceProvider : AuthenticationTokenProvider
    {
        private readonly object _sync = new Object();
        private readonly RandomNumberGenerator _rng = new RNGCryptoServiceProvider();
        private readonly IDictionary<string, DateTimeOffset?> _outstanding = new Dictionary<string, DateTimeOffset?>();

        public override void Create(AuthenticationTokenCreateContext context)
        {
            // make a random value
            var bytes = new byte[256/8];
            _rng.GetBytes(bytes);
            var nonce = TextEncodings.Base64Url.Encode(bytes);

            // add it as an extra property
            context.Ticket.Properties.Dictionary["nonce"] = nonce;
            lock (_sync)
            {
                // and make this server remember it was produced
                _outstanding[nonce] = context.Ticket.Properties.ExpiresUtc;
            }

            // the access code is the serialized ticket with the nonce buried in it
            context.SetToken(context.SerializeTicket());
        }

        public override void Receive(AuthenticationTokenReceiveContext context)
        {
            // deserialize and take ticket from context
            context.DeserializeTicket(context.Token);
            var ticket = context.Ticket;
            context.SetTicket(new AuthenticationTicket(null, new AuthenticationProperties()));

            if (ticket == null)
            {
                // no good if nothing there
                return;
            }

            string nonce;
            if (!ticket.Properties.Dictionary.TryGetValue("nonce", out nonce))
            {
                // no good if nonce property missing
                return;                
            }

            if (string.IsNullOrEmpty(nonce))
            {
                // no good if nonce null or empty
                return;
            }

            lock (_sync)
            {
                if (!_outstanding.Remove(nonce))
                {
                    // no good if nonce was already removed, or never added
                    return;
                }
            }

            // otherwise allow this ticket to be received
            context.SetTicket(ticket);
        }
    }
}