using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OAuth2;

namespace ClientApp.Controllers
{
    public class HomeController : Controller
    {
        private readonly WebServerClient _authServerClient;
        private readonly IAuthorizationState _authorizationRequest;

        public HomeController()
        {
            _authServerClient = new WebServerClient(
                new AuthorizationServerDescription
                    {
                        AuthorizationEndpoint = new Uri("http://localhost:9001/Authorize"),
                        TokenEndpoint = new Uri("http://localhost:9001/Token")
                    },
                "the-client",
                "the-client-secret");

            _authorizationRequest = new AuthorizationState
                {
                    Callback = new Uri("http://localhost:9002/Home/Return")
                };
        }

        public IAuthorizationState AccessTokenAuthorization
        {
            get
            {
                var accessToken = Session["access_token"] as string;
                if (String.IsNullOrEmpty(accessToken))
                {
                    return null;
                }
                return new AuthorizationState { AccessToken = accessToken };
            }
        }

        public ActionResult Index()
        {
            ViewBag.Message = "You are looking at the home page of the ClientApp.";

            return View();
        }

        public async Task<ActionResult> About()
        {
            ViewBag.Message = "Your app description page.";

            var accessToken = Session["access_token"] as string;
            if (String.IsNullOrEmpty(accessToken))
            {
                // we have no token, bounce the browser over to the server's /Authorize endpoint
                return new UserAuthorizationResult(_authServerClient.PrepareRequestUserAuthorization(_authorizationRequest));
            }

            // we do have an access_token, so add it as bearer auth header to outgoing requests
            var httpClient = new HttpClient(
                _authServerClient.CreateAuthorizingHandler(accessToken)
                );

            // call the server for data
            var me = await httpClient.GetAsync("http://localhost:9001/Me");

            // show it on the view
            ViewBag.Message = await me.Content.ReadAsStringAsync();

            return View();
        }

        public ActionResult Return()
        {
            // browser came back with an authenication code, now get the access_token directly from the server 
            var authorization = _authServerClient.ProcessUserAuthorization(Request);
            Session["access_token"] = authorization.AccessToken;

            // and go back to About
            return RedirectToAction("About");
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

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}
