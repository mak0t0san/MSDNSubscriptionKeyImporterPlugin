namespace MSDNSubscriptionKeyImporterPlugin
{
    using System.IO;

    using KeePass.DataExchange;
    using KeePass.Util.XmlSerialization;

    using KeePassLib;
    using KeePassLib.Interfaces;
    using KeePassLib.Security;

    internal class MicrosoftKeysExportFileFormatProvider : FileFormatProvider
    {
        public override bool SupportsImport => true;

        public override bool SupportsExport => false;

        public override string FormatName => "MSDN Subscription XML";

        public override string DefaultExtension => "xml";

        public override void Import(PwDatabase pwStorage, Stream sInput, IStatusLogger slLogger)
        {
            var serializer = new XmlSerializerEx(typeof(root));
            var document = serializer.Deserialize(sInput) as root;
            if (document == null)
            {
                return;
            }

            foreach (object documentItem in document.Items)
            {
                if (!(documentItem is rootYourKey))
                {
                    continue;
                }
                PwGroup msdnGroup = pwStorage.RootGroup.FindCreateGroup("Microsoft Product Keys", true);

                var yourKey = documentItem as rootYourKey;
                for (var i = 0; i < yourKey.Product_Key.Length; i++)
                {
                    rootYourKeyProduct_Key product = yourKey.Product_Key[i];
                    slLogger.SetText($"{product.Name} ({i + 1} of {yourKey.Product_Key.Length})", LogStatusType.Info);
                    AddProduct(pwStorage, msdnGroup, product);
                }
            }
        }

        private static void AddProduct(PwDatabase database, PwGroup group, rootYourKeyProduct_Key product)
        {
            var hasKeys = false;
            foreach (rootYourKeyProduct_KeyKey key in product.Key)
            {
                if (key.ID > 0)
                {
                    hasKeys = true;
                }
            }

            if (!hasKeys)
            {
                return;                
            }

            PwGroup productGroup = group.FindCreateGroup(product.Name, true);

            foreach (rootYourKeyProduct_KeyKey key in product.Key)
            {
                if (!GroupContainsKeyAsPassword(productGroup, key) && key.ID > 0)
                {
                    AddKey(database, productGroup, product, key);
                }
            }
        }

        private static void AddKey(PwDatabase database, PwGroup group, rootYourKeyProduct_Key product, rootYourKeyProduct_KeyKey key)
        {
            var entry = new PwEntry(true, true);

            group.AddEntry(entry, true);

            string note = (string.IsNullOrEmpty(key.ClaimedDate) ? "" : $"Claimed on : {key.ClaimedDate}\n\n") +
                product.KeyRetrievalNote;
            entry.Strings.Set(PwDefs.TitleField, new ProtectedString(database.MemoryProtection.ProtectTitle, key.Type));
            entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(database.MemoryProtection.ProtectPassword, key.Value));
            entry.Strings.Set(PwDefs.NotesField, new ProtectedString(database.MemoryProtection.ProtectNotes, note));
        }

        private static bool GroupContainsKeyAsPassword(PwGroup group, rootYourKeyProduct_KeyKey key)
        {
            foreach (PwEntry entry in group.Entries)
            {
                if (key.Value == entry.Strings.Get(PwDefs.PasswordField).ReadString())
                {
                    return true;
                }
            }
            return false;
        }
    }
}