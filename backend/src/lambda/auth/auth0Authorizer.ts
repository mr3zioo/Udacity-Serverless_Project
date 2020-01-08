import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
const cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJDwZDWGgBOdBNMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi03dDRrMXAtZC5hdXRoMC5jb20wHhcNMjAwMTA3MTczMDI3WhcNMzMw
OTE1MTczMDI3WjAhMR8wHQYDVQQDExZkZXYtN3Q0azFwLWQuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyIra+OcZKZf4VnbFtG1kWyjx
X/lY5CZJqk7xTVK2Pegsne/3WGvpXJcITKASFtyNowLGQx+pKLSqJ1c2CduDdnUL
a48CDewRzfXr4LghaOUMBYcqrdYxEVidg+zY4AoNVnMDmVY9qpBXIg+YSZYWoB3W
aH9ulDKv8Fi12A/GF2VLPAOIvegtTomEuRdKSg/+32dZRVFuOM/dsy+i++qzRZEk
MjKsDgavb1nYX1qqKFQxiAROE3R53vCSjoeYsxi2o/EWqSn1qzDTmSmr6no7h/t8
77Wm5yI+7d8n3omvnzL68uaFWSQS7KaXSrvpsC0c9T/ueTuIW/hS6ZxprHCXbwID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRg+hxxqQme75eq2Hsn
yLjfuWuSujAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBADWFECcd
gBaMkXlUwzlI9QCFN140X6h6z0UExHR1sV7FpU3+gbj4NZsRQTXWmxFF6JZuDEPc
jtTw7Jud/dn1Iq2tF/yXo4hxcMo+E3Sbry4gF28K6JfPxOexmWzjYuPy4e1XZuBf
GPJV8n1gCvtnUjs3YXZbV59JjOXD1oWazICFzb9W8DX/wFflYZEkytwngn/NUZ1c
6uSbBFsrQ6Q8/XrTvEHJaAHfkbJVILJOyCpT9NpACvRze8m9CYvkW015YuM17UL7
m7hABJH3zhkUsKUzZ6vhrwFy6hqL7y5IEn217tBtl2U2FqPyL6Ma9A+TXOPWfGst
SeASqPxZWLEKVp0=
-----END CERTIFICATE-----

`;
export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader);
  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token, cert, { algorithms: ["RS256"] }) as JwtPayload;
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
