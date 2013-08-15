using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Mvc;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth2;

namespace ClientApp.Controllers
{
    public class ShowController : Controller
    {
        private readonly WebServerClient _authServerClient;

        public ShowController()
        {
            _authServerClient = new WebServerClient(
                new AuthorizationServerDescription
                    {
                        AuthorizationEndpoint = new Uri("http://localhost:9001/Authorize"),
                        TokenEndpoint = new Uri("http://localhost:9001/Token")
                    },
                "the-client",
                "the-client-secret");
        }

        //
        // GET: /Show/

        public async Task<ActionResult> Me()
        {
            var accessToken = Session["access_token"] as string;
            if (String.IsNullOrEmpty(accessToken))
            {
                // we have no token, bounce the browser over to the server's /Authorize endpoint, and come back to /Return
                var response = _authServerClient.PrepareRequestUserAuthorization(
                    returnTo: new Uri("http://localhost:9002/Show/Return"));
                
                return new UserAuthorizationResult(response);
            }

            // we do have an access_token, so add it as bearer auth header to outgoing requests
            var httpClient = new HttpClient(_authServerClient.CreateAuthorizingHandler(accessToken));

            // call the server for data
            var me = await httpClient.GetAsync("http://localhost:9001/Me");

            // show it on the view
            ViewBag.Me = await me.Content.ReadAsStringAsync();

            return View();
        }

        class UserAuthorizationResult : ActionResult
        {
            private readonly OutgoingWebResponse _outgoingWebResponse;

            public UserAuthorizationResult(OutgoingWebResponse outgoingWebResponse)
            {
                _outgoingWebResponse = outgoingWebResponse;
            }

            public override void ExecuteResult(ControllerContext context)
            {
                _outgoingWebResponse.Send(context.HttpContext);
            }
        }

        //
        // GET: /Show/Return

        public ActionResult Return()
        {
            // browser came back with an authenication code, now get the access_token directly from the server 
            var authorization = _authServerClient.ProcessUserAuthorization(Request);
            Session["access_token"] = authorization.AccessToken;

            // and go back to About
            return RedirectToAction("Me");
        }

        public ActionResult ForgetToken()
        {
            Session.Remove("access_token");
            return Redirect("/");
        }
    }
}
