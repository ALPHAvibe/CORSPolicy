using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Cors;
using System.Web.Http.Cors;

namespace Business.Attributes
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
    public class CORSPolicy : Attribute, ICorsPolicyProvider
    {
        private HashSet<string> _domains = new HashSet<string> { "domain1", "domain2" };

        private List<string> _methods;

        public CORSPolicy(string methods = null) //attribute filter param can only be constants
        {
            _methods = String.IsNullOrEmpty(methods) ? null : methods.Split(',').ToList();
        }

        public Task<CorsPolicy> GetCorsPolicyAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var policy = BuildPolicy();
            var headerValues = request.Headers.GetValues("Origin");

            if(headerValues != null)
            {
                var originValue = headerValues.FirstOrDefault();

                if (OriginAllowed(originValue))
                {
                    policy.Origins.Add(originValue);
                }
            }

            return Task.FromResult(policy);
        }

        private bool OriginAllowed(string originValue)
        {
            Uri originUri = null;

            if (!String.IsNullOrEmpty(originValue)
                && Uri.TryCreate(originValue, UriKind.Absolute, out originUri))
            {
                var authority = originUri.Authority.ToLowerInvariant();
                var parts = originUri.Host.Split('.');
                var domain = parts[1] + "." + parts[2];

                return (_domains.Contains(domain));
            }

            return false;
        }

        private CorsPolicy BuildPolicy()
        {
            var haveMethods = _methods != null && _methods.Any();

            var policy = new CorsPolicy
            {
                AllowAnyMethod = haveMethods,
                AllowAnyHeader = true,
                SupportsCredentials = true,
                PreflightMaxAge = 600,
            };

            if (haveMethods)
            {
                _methods.ForEach(method => policy.Methods.Add(method));
            }

            return policy;
        }
    }
}
