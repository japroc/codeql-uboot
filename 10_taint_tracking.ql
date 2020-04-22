import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(
            MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") |
            this = mi.getExpr()
        )
    }
}

class MyCfg extends TaintTracking::Configuration {
    MyCfg() { this = "TaintAnalyze from NetworkByteSwap to memcpy" }

    override predicate isSource(DataFlow::Node node) {
        node.asExpr() instanceof NetworkByteSwap
    }

    override predicate isSink(DataFlow::Node node) {
        exists(
            FunctionCall fc |
            fc.getTarget().hasName("memcpy") |
            fc.getArgument(2) = node.asExpr()
        )
    }
}

from DataFlow::Node source, DataFlow::Node sink, MyCfg conf
where conf.hasFlow(source, sink)
select source, sink, conf
