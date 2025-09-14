using System.Text;

static class DbUrl
{
    public static string NormalizeDbUrl(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return input ?? string.Empty;
        // Already looks like key=value;
        if (input.Contains('=') && input.Contains(';')) return input; // assume already proper
        // Expect formats like: postgres://user:pass@host:5432/dbname or postgresql://
        if (input.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) ||
            input.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(input, UriKind.Absolute, out var uri)) return input; // fallback
            var userInfo = uri.UserInfo.Split(':');
            var username = Uri.UnescapeDataString(userInfo.ElementAtOrDefault(0) ?? "");
            var password = Uri.UnescapeDataString(userInfo.ElementAtOrDefault(1) ?? "");
            var host = uri.Host;
            var port = uri.IsDefaultPort ? 5432 : uri.Port;
            var database = uri.AbsolutePath.TrimStart('/');
            var builder = new StringBuilder();
            void Add(string k, string v) { if (!string.IsNullOrEmpty(v)) builder.Append(k).Append('=').Append(v).Append(';'); }
            Add("Host", host);
            Add("Port", port.ToString());
            Add("Username", username);
            Add("Password", password);
            Add("Database", database);
            var q = uri.Query;
            if (!string.IsNullOrEmpty(q))
            {
                var query = System.Web.HttpUtility.ParseQueryString(q);
                foreach (var key in query.AllKeys!)
                {
                    var val = query[key];
                    if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(val))
                        Add(key!, val!);
                }
            }
            return builder.ToString();
        }
        return input; // unknown format, just return
    }
}
