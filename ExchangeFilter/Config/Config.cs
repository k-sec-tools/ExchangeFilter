using System.Collections.Generic;

namespace ExchangeFilter
{
    /// <summary>
    /// Compile time configuration class including default values for configuration parameters
    /// You can change values here to suit your needs.
    /// </summary>
    public static class Config
    {
        public const string ConfigFileName = "config.xml";
        //public const string ConfigDirectoryName = "Configuration";
        public const string ConfigSchemaFilename = "config.xsd";
        public const string DefaultConfigFileName = "default_config.xml";
        public const string ConfigFileSevenZipLibraryPath = "C:\\Path\\To\\7-Zip\\7z.dll";

        // default values for parameters not found in config
        public const int AttachmentSizeThresholdDefault = 2048;
        public const int AttachmentArchiveDepth = 2;
        public const int AttachmentArchiveProcessingTime = 500;
        public const int GCCollectInterval = 60;
        public const bool ScanArchivesDefault = false;
        public const bool BlockUncheckedArchives = false;
        public const bool MailboxMethodSafeDefault = true;
        //public const bool ScanOfficeDocumentsDefault = true;
        public const bool CheckMessageBodyDefault = false;
        public const bool CheckMessageSubjectDefault = false;
        public const bool CheckMessageHeadersDefault = false;
        public const bool CheckAttachmentsDefault = false;
        public const bool CheckSmtpSessionDefault = false;
        public const bool AgentEnabledDefault = true;
        public const bool UseMetricsDefault = false;
        public const bool LogOnlyModeDefault= false;
        public const int AgentModuleWeightDefault = 4;

        public const string SusupiciousMailHeaderDefault = "X-Malicious-Message";
        public const string ProcessedMailHeaderDefault = "X-Processed-Message";
        public const string WhiteListedMailHeaderDefault = "X-Whitelisted-Message";
        public const string HeaderValueDefault = "YES";
        public const Header.HeaderValueTypeEnum HeaderValueTypeDefault = Header.HeaderValueTypeEnum.Wildcard;
        public const string AgentActionDefault = "header";


        // hardcoded list of supported archive file types
        public static readonly IEnumerable<string> ArchiveFileTypesDefault = new[]
        {
            "*.7z",
            "*.zip"
        };

    }
}
