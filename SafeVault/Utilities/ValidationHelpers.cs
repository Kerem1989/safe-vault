namespace SafeVault.Utilities ;
using System.Text.RegularExpressions;
using System.Web;

    public class ValidationHelpers
    {
        private static readonly string[] BlackListTags = { "script", "iframe", "object", "embed", "form" };
        private static readonly string[] BlackListAttributes = { "onload", "onclick", "onerror", "href", "src" };

        public static bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return false;
            }
            if(username.All(c => char.IsLetterOrDigit(c) || c == '@' || c == '.'|| c == '-' || c == '_'))
                return true;
            return false;
        }

        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                return false;
            }

            // Blacklist HTML/XSS patterns
            foreach (var tag in BlackListTags)
            {
                var tagRegex = new Regex($"<\\/?\\s*{tag}\\s*[^>]*>", RegexOptions.IgnoreCase);
                if (tagRegex.IsMatch(email))
                    return false;
            }

            foreach (var attr in BlackListAttributes)
            {
                var attrRegex = new Regex($"{attr}\\s*=\\s*['\"].*?['\"]", RegexOptions.IgnoreCase);
                if (attrRegex.IsMatch(email))
                    return false;
            }

            var jsLinkRegex = new Regex(@"href\s*=\s*['""]javascript:[^'""]*['""]", RegexOptions.IgnoreCase);
            if (jsLinkRegex.IsMatch(email))
                return false;

            var plainLinkRegex = new Regex(@"(http|https):\/\/[^\s<>]+", RegexOptions.IgnoreCase);
            if (plainLinkRegex.IsMatch(email))
                return false;

            var emailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
    
            if (emailRegex.IsMatch(email))
            {
                email = ValidationHelpers.Sanitize(email);
                return true;
            }

            return false;
        }

        public static string Sanitize(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // HTML-encode so any injected markup is rendered as inert text, never executed.
            return HttpUtility.HtmlEncode(input);
        }
    }
