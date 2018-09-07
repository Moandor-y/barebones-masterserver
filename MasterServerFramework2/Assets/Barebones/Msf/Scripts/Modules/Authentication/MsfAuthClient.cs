using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Barebones.Networking;

namespace Barebones.MasterServer
{
    public class MsfAuthClient : MsfBaseClient
    {
        public delegate void LoginCallback(AccountInfoPacket accountInfo,
                                           string error);

        private bool _isLoggingIn;

        public bool IsLoggedIn { get; protected set; }

        public AccountInfoPacket AccountInfo;

        public event Action LoggedIn;
        public event Action Registered;
        public event Action LoggedOut;

        public MsfAuthClient(IClientSocket connection) : base(connection) { }

        /// <summary>
        /// Sends a registration request to server
        /// </summary>
        /// <param name="data"></param>
        /// <param name="callback"></param>
        public async Task Register(Dictionary<string, string> data,
                                   SuccessCallback callback)
        {
            await Register(data, callback, Connection);
        }

        /// <summary>
        /// Sends a registration request to given connection
        /// </summary>
        public async Task Register(Dictionary<string, string> data,
                                   SuccessCallback callback,
                                   IClientSocket connection)
        {
            if (_isLoggingIn)
            {
                callback.Invoke(false, "Log in is already in progress");
                return;
            }

            if (IsLoggedIn)
            {
                callback.Invoke(false, "Already logged in");
                return;
            }

            if (!connection.IsConnected)
            {
                callback.Invoke(false, "Not connected to server");
                return;
            }

            // We first need to get an aes key 
            // so that we can encrypt our login data
            var aesKey = await Msf.Security.GetAesKey(connection);
            if (aesKey == null)
            {
                callback.Invoke(
                    false, "Failed to register due to security issues");
                return;
            }

            var encryptedData =
                await Msf.Security.EncryptAES(data.ToBytes(), aesKey);

            connection.SendMessage(
                (short) MsfOpCodes.RegisterAccount,
                encryptedData, (status, response) =>
                {
                    if (status != ResponseStatus.Success)
                    {
                        callback.Invoke(
                            false, response.AsString("Unknown error"));
                        return;
                    }

                    callback.Invoke(true, null);

                    Registered?.Invoke();
                });
        }

        /// <summary>
        ///     Initiates a log out. In the process, disconnects and connects
        ///     back to the server to ensure no state data is left on the server.
        /// </summary>
        public void LogOut()
        {
            LogOut(Connection);
        }

        /// <summary>
        ///     Initiates a log out. In the process, disconnects and connects
        ///     back to the server to ensure no state data is left on the server.
        /// </summary>
        public void LogOut(IClientSocket connection)
        {
            if (!IsLoggedIn)
                return;

            IsLoggedIn = false;
            AccountInfo = null;

            if ((connection != null) && connection.IsConnected)
                connection.Reconnect();

            LoggedOut?.Invoke();
        }

        /// <summary>
        /// Sends a request to server, to log in as a guest
        /// </summary>
        /// <param name="callback"></param>
        public async Task LogInAsGuest(LoginCallback callback)
        {
            await LogIn(new Dictionary<string, string>()
            {
                {"guest", ""}
            }, callback, Connection);
        }

        /// <summary>
        /// Sends a request to server, to log in as a guest
        /// </summary>
        public async Task LogInAsGuest(LoginCallback callback,
                                       IClientSocket connection)
        {
            await LogIn(new Dictionary<string, string>()
            {
                {"guest", ""}
            }, callback, connection);
        }

        /// <summary>
        /// Sends a login request, using given credentials
        /// </summary>
        public async Task LogIn(string username, string password,
                                LoginCallback callback,
                                IClientSocket connection)
        {
            await LogIn(new Dictionary<string, string>
            {
                {"username", username},
                {"password", password}
            }, callback, connection);
        }

        /// <summary>
        /// Sends a login request, using given credentials
        /// </summary>
        public async Task LogIn(string username, string password,
                                LoginCallback callback)
        {
            await LogIn(username, password, callback, Connection);
        }

        /// <summary>
        /// Sends a generic login request
        /// </summary>
        /// <param name="data"></param>
        /// <param name="callback"></param>
        public async Task LogIn(Dictionary<string, string> data,
                                LoginCallback callback)
        {
            await LogIn(data, callback, Connection);
        }

        /// <summary>
        /// Sends a generic login request
        /// </summary>
        public async Task LogIn(Dictionary<string, string> data,
                                LoginCallback callback,
                                IClientSocket connection)
        {
            if (!connection.IsConnected)
            {
                callback.Invoke(null, "Not connected to server");
                return;
            }

            _isLoggingIn = true;

            // We first need to get an aes key 
            // so that we can encrypt our login data
            var aesKey = await Msf.Security.GetAesKey(connection);
            if (aesKey == null)
            {
                _isLoggingIn = false;
                callback.Invoke(
                    null, "Failed to log in due to security issues");
                return;
            }

            var encryptedData =
                await Msf.Security.EncryptAES(data.ToBytes(), aesKey);

            connection.SendMessage(
                (short) MsfOpCodes.LogIn,
                encryptedData,
                (status, response) =>
                {
                    _isLoggingIn = false;

                    if (status != ResponseStatus.Success)
                    {
                        callback.Invoke(
                            null, response.AsString("Unknown error"));
                        return;
                    }

                    IsLoggedIn = true;

                    AccountInfo = response.Deserialize(new AccountInfoPacket());

                    callback.Invoke(AccountInfo, null);

                    LoggedIn?.Invoke();
                });
        }

        /// <summary>
        /// Sends an e-mail confirmation code to the server
        /// </summary>
        /// <param name="code"></param>
        /// <param name="callback"></param>
        public void ConfirmEmail(string code, SuccessCallback callback)
        {
            ConfirmEmail(code, callback, Connection);
        }

        /// <summary>
        /// Sends an e-mail confirmation code to the server
        /// </summary>
        public void ConfirmEmail(string code, SuccessCallback callback,
                                 IClientSocket connection)
        {
            if (!connection.IsConnected)
            {
                callback.Invoke(false, "Not connected to server");
                return;
            }

            if (!IsLoggedIn)
            {
                callback.Invoke(false, "You're not logged in");
                return;
            }

            connection.SendMessage(
                (short) MsfOpCodes.ConfirmEmail,
                code,
                (status, response) =>
                {
                    if (status != ResponseStatus.Success)
                    {
                        callback.Invoke(
                            false, response.AsString("Unknown error"));
                        return;
                    }

                    callback.Invoke(true, null);
                });
        }

        /// <summary>
        /// Sends a request to server, to ask for an e-mail confirmation code
        /// </summary>
        /// <param name="callback"></param>
        public void RequestEmailConfirmationCode(SuccessCallback callback)
        {
            RequestEmailConfirmationCode(callback, Connection);
        }

        /// <summary>
        /// Sends a request to server, to ask for an e-mail confirmation code
        /// </summary>
        public void RequestEmailConfirmationCode(
            SuccessCallback callback, IClientSocket connection)
        {
            if (!connection.IsConnected)
            {
                callback.Invoke(false, "Not connected to server");
                return;
            }

            if (!IsLoggedIn)
            {
                callback.Invoke(false, "You're not logged in");
                return;
            }

            connection.SendMessage(
                (short) MsfOpCodes.RequestEmailConfirmCode,
                (status, response) =>
                {
                    if (status != ResponseStatus.Success)
                    {
                        callback.Invoke(
                            false, response.AsString("Unknown error"));
                        return;
                    }

                    callback.Invoke(true, null);
                });
        }

        /// <summary>
        /// Sends a request to server, to ask for a password reset
        /// </summary>
        public void RequestPasswordReset(string email, SuccessCallback callback)
        {
            RequestPasswordReset(email, callback, Connection);
        }

        /// <summary>
        /// Sends a request to server, to ask for a password reset
        /// </summary>
        public void RequestPasswordReset(string email, SuccessCallback callback,
                                         IClientSocket connection)
        {
            if (!connection.IsConnected)
            {
                callback.Invoke(false, "Not connected to server");
                return;
            }

            connection.SendMessage((short) MsfOpCodes.PasswordResetCodeRequest,
                                   email, (status, response) =>
                                   {
                                       if (status != ResponseStatus.Success)
                                       {
                                           callback.Invoke(
                                               false,
                                               response.AsString(
                                                   "Unknown error"));
                                           return;
                                       }

                                       callback.Invoke(true, null);
                                   });
        }

        /// <summary>
        /// Sends a new password to server
        /// </summary>
        public void ChangePassword(PasswordChangeData data,
                                   SuccessCallback callback)
        {
            ChangePassword(data, callback, Connection);
        }

        /// <summary>
        /// Sends a new password to server
        /// </summary>
        public void ChangePassword(PasswordChangeData data,
                                   SuccessCallback callback,
                                   IClientSocket connection)
        {
            if (!connection.IsConnected)
            {
                callback.Invoke(false, "Not connected to server");
                return;
            }

            var dictionary = new Dictionary<string, string>()
            {
                {"email", data.Email},
                {"code", data.Code},
                {"password", data.NewPassword}
            };

            connection.SendMessage(
                (short) MsfOpCodes.PasswordChange,
                dictionary.ToBytes(),
                (status, response) =>
                {
                    if (status != ResponseStatus.Success)
                    {
                        callback.Invoke(
                            false, response.AsString("Unknown error"));
                        return;
                    }

                    callback.Invoke(true, null);
                });
        }
    }
}
