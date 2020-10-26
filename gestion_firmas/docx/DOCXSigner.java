/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.rubrica.sign.docx;


import org.apache.poi.poifs.crypt.dsig.SignatureInfo;
import org.apache.poi.poifs.crypt.dsig.SignatureInfo.SignaturePart;
import org.apache.poi.poifs.crypt.dsig.SignatureConfig;
import org.apache.poi.poifs.crypt.dsig.facets.EnvelopedSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.KeyInfoSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.XAdESSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.XAdESXLSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.services.RevocationData;
import org.apache.poi.poifs.crypt.dsig.services.RevocationDataService;
import org.apache.poi.poifs.crypt.dsig.services.TimeStampService;
import org.apache.poi.poifs.crypt.dsig.services.TimeStampServiceValidator;
import org.apache.poi.poifs.crypt.dsig.facets.Office2010SignatureFacet;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackageAccess;
import org.apache.poi.util.LocaleUtil;

import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import io.rubrica.exceptions.RubricaException;
import io.rubrica.exceptions.InvalidFormatException;
import io.rubrica.sign.SignInfo;
import io.rubrica.sign.Signer;
import io.rubrica.sign.cms.DatosUsuario;
import io.rubrica.utils.BouncyCastleUtils;
import io.rubrica.utils.Utils;

public class PDFSigner implements Signer {

    private static final Logger logger = Logger.getLogger(PDFSigner.class.getName());
    
    public static final String SIGNING_REASON = "signingReason";
    public static final String SIGNING_LOCATION = "signingLocation";
    public static final String SIGN_TIME = "signTime";
    public static final String SIGNATURE_PAGE = "signingPage";
    public static final String LAST_PAGE = "0";
    public static final String FONT_SIZE = "3";
    public static final String TYPE_SIG = "information1";
    public static final String INFO_QR = "";

    static {
        BouncyCastleUtils.initializeBouncyCastle();
    }

    // ETSI TS 102 778-1 V1.1.1 (2009-07)
    // PAdES Basic - Profile based on ISO 32000-1
    /**
     * Algoritmos soportados:
     *
     * <li><i>SHA1withRSA</i></li>
     * <li><i>SHA256withRSA</i></li>
     * <li><i>SHA384withRSA</i></li>
     * <li><i>SHA512withRSA</i></li>
     *
     * @param xParams
     * @throws io.rubrica.exceptions.RubricaException
     * @throws java.io.IOException
     * @throws com.lowagie.text.exceptions.BadPasswordException
     */
    @Override
    public byte[] sign(byte[] data, String algorithm, PrivateKey key, Certificate[] certChain, Properties xParams)
            throws RubricaException, IOException, BadPasswordException {

        Properties extraParams = xParams != null ? xParams : new Properties();

        X509Certificate x509Certificate = (X509Certificate) certChain[0];

        // Motivo de la firma
        String reason = extraParams.getProperty(SIGNING_REASON);

        // Lugar de realizacion de la firma
        String location = extraParams.getProperty(SIGNING_LOCATION);

        // Fecha y hora de la firma, en formato ISO-8601
        String signTime = extraParams.getProperty(SIGN_TIME);

        //Leer DOCX 
        InputStream myInputStream = new ByteArrayInputStream(data); 
        OPCPackage pkg = OPCPackage.open(myInputStream);
        
        // filling the SignatureConfig entries minimally
        SignatureConfig signatureConfig = new SignatureConfig();
        signatureConfig.setKey((PrivateKey)key);

        signatureConfig.setExecutionTime(SIGN_TIME);
        signatureConfig.setDigestAlgo(algorithm);

        // Only use these Signature Facets, the others break Office verification
        // see the test Apache POI test code for more facets
        signatureConfig.addSignatureFacet(new EnvelopedSignatureFacet());
        signatureConfig.addSignatureFacet(new KeyInfoSignatureFacet());

        signatureConfig.setSigningCertificateChain(Collections.singletonList(x509Certificate));
        signatureConfig.setOpcPackage(pkg);

        // adding the signature document to the package
        SignatureInfo si = new SignatureInfo();
        si.setSignatureConfig(signatureConfig);
        si.confirmSignature();
        pkg.close();

        return IOUtils.toByteArray(myInputStream);
    }

    
}
