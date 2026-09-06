/**
 * @name lxml parser configured to resolve external entities
 * @description Company policy XML-001 requires every XML parser to be created
 *              with resolve_entities=False, load_dtd=False and no_network=True.
 *              A parser that resolves entities allows an attacker-supplied
 *              document to read local files and make outbound requests from
 *              the server (XXE / SSRF).
 * @kind problem
 * @problem.severity error
 * @security-severity 8.2
 * @precision high
 * @id py/company/unsafe-xml-parser-configuration
 * @tags security
 *       company-policy
 *       external/cwe/cwe-611
 *       external/cwe/cwe-827
 */

import python
import semmle.python.ApiGraphs

/**
 * Holds if `call` constructs an lxml parser whose `option` is set to the
 * dangerous value: `True` for entity/DTD loading, `False` for network denial.
 */
predicate unsafeParserOption(API::CallNode call, string option, string value) {
  call = API::moduleImport("lxml").getMember("etree").getMember("XMLParser").getACall() and
  (
    option in ["resolve_entities", "load_dtd"] and
    call.getArgByName(option).getALocalSource().asExpr() instanceof True and
    value = "True"
    or
    option = "no_network" and
    call.getArgByName(option).getALocalSource().asExpr() instanceof False and
    value = "False"
  )
}

from API::CallNode call, string option, string value
where unsafeParserOption(call, option, value)
select call,
  "XML parser created with " + option + "=" + value +
    ", which permits external entity resolution (policy XML-001)."
