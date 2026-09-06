/**
 * @name Outbound request with TLS verification disabled
 * @description Company policy CRY-002 requires that all outbound HTTPS calls
 *              validate the server certificate. Passing verify=False to the
 *              requests library disables validation and exposes the call to
 *              interception on the network path.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.4
 * @precision very-high
 * @id py/company/tls-verification-disabled
 * @tags security
 *       company-policy
 *       external/cwe/cwe-295
 */

import python
import semmle.python.ApiGraphs

from API::CallNode call, DataFlow::Node verifyArg
where
  call =
    API::moduleImport("requests")
        .getMember(["get", "post", "put", "patch", "delete", "head", "options", "request"])
        .getACall() and
  verifyArg = call.getArgByName("verify") and
  // getALocalSource() also catches `VERIFY = False` assigned to a local and
  // then passed in — the shape this bug usually takes once someone "fixes" it
  // by hoisting the literal into a constant.
  verifyArg.getALocalSource().asExpr() instanceof False
select call,
  "Outbound request disables TLS certificate verification (verify=False), violating policy CRY-002."
