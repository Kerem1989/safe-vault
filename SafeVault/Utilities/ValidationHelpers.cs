namespace SafeVault.Utilities ;

    public class ValidationHelpers
    {
        public static bool IsValidUsername(string username)
        {
            if(username.All(c => char.IsLetterOrDigit(c) || c == '@' || c == '.'))
                return true;
            return false;
        }
    }