using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Packaging;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SignVsixTool
{
	internal class Program
	{
		private static void Main(string[] args)
		{
			// first argument - path to VSIX package
			var paramPathPackage = args[0].Replace("\"", "");
			// second argument - path to PFX certificate
			var paramPathCertificate = args[1].Replace("\"", "");
			
			// third argument - password for the certificate
			var paramPassword = args.Length > 2 ? args[2] : string.Empty;

			// open VSIX package
			var package = Package.Open(paramPathPackage, FileMode.Open);

			// load certificate
			var certificate = File.ReadAllBytes(paramPathCertificate);

			// sign all parts of the package
			var signatureManager = new PackageDigitalSignatureManager(package)
			{
				CertificateOption = CertificateEmbeddingOption.InSignaturePart
			};

			var partsToSign = package.GetParts().Select(packagePart => packagePart.Uri).ToList();

			partsToSign.Add(PackUriHelper.GetRelationshipPartUri(signatureManager.SignatureOrigin));
			partsToSign.Add(signatureManager.SignatureOrigin);
			partsToSign.Add(PackUriHelper.GetRelationshipPartUri(new Uri("/", UriKind.RelativeOrAbsolute)));

			try
			{
				signatureManager.Sign(partsToSign, new X509Certificate2(certificate, paramPassword));
			}
			catch (CryptographicException cryptographicException)
			{
				Console.WriteLine("Signing failed: {0}", cryptographicException.Message);
			}
		}
	}
}
