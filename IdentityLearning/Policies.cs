namespace IdentityLearning
{
    public static class Policies
    {
        public class Authentification
        {
            public const string V1 = "V1";

            public const string V2 = "V2";

            public const string V3 = "V3";
        }

        public class Authorization
        {
            public const string Authorized = "Authorized";

            public const string HasNameClaim = "HasNameClaim";

            public const string HasLetterAInNameAndRole = "HasLetterAInNameAndRole";

            public const string AtLeast21 = "AtLeast21";
        }
    }
}
