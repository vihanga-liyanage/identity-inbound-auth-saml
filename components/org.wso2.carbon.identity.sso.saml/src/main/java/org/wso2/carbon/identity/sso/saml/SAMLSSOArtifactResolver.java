package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.dao.SAMLArtifactDAO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.UUID;

public class SAMLSSOArtifactResolver {

    private static Log log = LogFactory.getLog(SAMLSSOArtifactResolver.class);

    /**
     * Build and return an ArtifactResponse object when SAML artifact is given.
     *
     * @param artifact     SAML artifact given by the requester.
     * @param id           ID of the SAMl ArtifactResolve object. Goes back as the InResponseTo in ArtifactResponse.
     * @param issueInstant Issue instance came with SAMl ArtifactResolve object.
     * @return Built ArtifactResponse object.
     * @throws IdentityException
     */
    public ArtifactResponse resolveArtifact(String artifact, String id, String issueInstant) throws IdentityException {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<ArtifactResponse> artifactResolveBuilder =
                (SAMLObjectBuilder<ArtifactResponse>) builderFactory.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
        ArtifactResponse artifactResponse = artifactResolveBuilder.buildObject();

        Assertion assertion = null;

        try {
            // Decode and depart SAML artifact.
            byte[] artifactArray = Base64.decode(artifact);
            byte[] typeCode = new byte[2];
            byte[] endpointIndex = new byte[2];
            byte[] sourceID = new byte[20];
            byte[] messageHandler = new byte[20];

            System.arraycopy(artifactArray, 0, typeCode, 0, 2);
            System.arraycopy(artifactArray, 2, endpointIndex, 0, 2);
            System.arraycopy(artifactArray, 4, sourceID, 0, 20);
            System.arraycopy(artifactArray, 24, messageHandler, 0, 20);

            // Get SAML assertion from the database.
            SAMLArtifactDAO samlArtifactDAO = new SAMLArtifactDAO();
            assertion = samlArtifactDAO.getSAMLAssertion(typeCode, endpointIndex, sourceID, messageHandler);

        } catch (Exception e) {
            log.warn("Invalid SAML artifact : " + artifact);
        }

        log.info("Assertion: " + assertion);

        // Build ArtifactResponse object
        artifactResponse.setVersion(SAMLVersion.VERSION_20);
        artifactResponse.setID(UUID.randomUUID().toString());
        artifactResponse.setIssueInstant(new DateTime(issueInstant));
        artifactResponse.setInResponseTo(id);
        artifactResponse.setIssuer(SAMLSSOUtil.getIssuer());

        SAMLObjectBuilder<StatusCode> statusCodeBuilder =
                (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        SAMLObjectBuilder<Status> statusBuilder =
                (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        artifactResponse.setStatus(status);

        artifactResponse.setMessage(assertion);

        // TODO: 7/6/18 Sign response

        return artifactResponse;
    }
}