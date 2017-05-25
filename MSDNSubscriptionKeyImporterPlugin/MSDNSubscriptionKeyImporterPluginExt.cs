namespace MSDNSubscriptionKeyImporterPlugin
{
    using KeePass.Plugins;

    public sealed class MSDNSubscriptionKeyImporterPluginExt : Plugin
    {
        private IPluginHost _host;

        private MicrosoftKeysExportFileFormatProvider _provider;

        public override bool Initialize(IPluginHost host)
        {
            _host = host;
            _provider = new MicrosoftKeysExportFileFormatProvider();

            _host.FileFormatPool.Add(_provider);

            return true;
        }

        public override void Terminate()
        {
            _host.FileFormatPool.Remove(_provider);
        }
    }
}