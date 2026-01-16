#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

using namespace clang;
using namespace ento;

namespace {

struct PointerState {
  enum Kind { Owned, MaybeReleased, Released };

  Kind K;
  const Stmt *ConditionalReleaseCall;

  PointerState(Kind k, const Stmt *S = nullptr) : K(k), ConditionalReleaseCall(S) {}

  bool isMaybeReleased() const { return K == MaybeReleased; }
  bool isReleased() const { return K == Released; }
  bool isOwned() const { return K == Owned; }

  static PointerState getOwned() { return PointerState(Owned); }
  static PointerState getMaybeReleased(const Stmt *S) { return PointerState(MaybeReleased, S); }
  static PointerState getReleased() { return PointerState(Released); }

  bool operator==(const PointerState &O) const {
    return K == O.K && ConditionalReleaseCall == O.ConditionalReleaseCall;
  }

  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
    ID.AddPointer(ConditionalReleaseCall);
  }
};

class ConditionalOwnershipChecker
    : public Checker<check::PostCall, check::PreCall, check::DeadSymbols> {

  mutable std::unique_ptr<BugType> BT;

  bool isReleaseFunction(const CallEvent &Call) const {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II) return false;
    StringRef Name = II->getName();
    return Name == "efa_rdm_pke_release_rx" ||
           Name == "efa_rdm_pke_release_tx" ||
           Name == "efa_rdm_pke_release" ||
           Name == "efa_rdm_pke_release_rx_list" ||
           Name == "efa_rdm_rxe_release" ||
           Name == "efa_rdm_txe_release" ||
           Name == "efa_rdm_rxe_release_internal" ||
           Name == "ofi_buf_free";
  }

  bool isConditionalReleaseFunction(const CallEvent &Call) const {
    const IdentifierInfo *II = Call.getCalleeIdentifier();
    if (!II) return false;
    StringRef Name = II->getName();
    return Name == "efa_rdm_pke_copy_payload_to_ope" ||
           Name == "efa_rdm_pke_handle_data_copied" ||
           Name == "efa_rdm_ep_flush_queued_blocking_copy_to_hmem" ||
           Name == "efa_rdm_pke_queued_copy_payload_to_hmem" ||
           Name == "efa_rdm_pke_copy_payload_to_cuda";
  }

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkDeadSymbols(SymbolReaper &SR, CheckerContext &C) const;
};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(PointerStateMap, SymbolRef, PointerState)

void ConditionalOwnershipChecker::checkPostCall(const CallEvent &Call,
                                                 CheckerContext &C) const {
  if (!isConditionalReleaseFunction(Call) || Call.getNumArgs() < 1)
    return;

  SVal Arg = Call.getArgSVal(0);
  SymbolRef Sym = Arg.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const PointerState *PS = State->get<PointerStateMap>(Sym);

  if (!PS || PS->isOwned()) {
    State = State->set<PointerStateMap>(Sym,
        PointerState::getMaybeReleased(Call.getOriginExpr()));
    C.addTransition(State);
  }
}

void ConditionalOwnershipChecker::checkPreCall(const CallEvent &Call,
                                                CheckerContext &C) const {
  if (!isReleaseFunction(Call) || Call.getNumArgs() < 1)
    return;

  SVal Arg = Call.getArgSVal(0);
  SymbolRef Sym = Arg.getAsSymbol();
  if (!Sym)
    return;

  ProgramStateRef State = C.getState();
  const PointerState *PS = State->get<PointerStateMap>(Sym);

  if (PS && (PS->isMaybeReleased() || PS->isReleased())) {
    if (!BT)
      BT.reset(new BugType(this, "Potential double free", categories::MemoryError));

    ExplodedNode *N = C.generateNonFatalErrorNode(State);
    if (!N) return;

    auto Report = std::make_unique<PathSensitiveBugReport>(*BT,
        "Pointer may have already been released", N);
    Report->addRange(Call.getSourceRange());
    Report->markInteresting(Sym);
    C.emitReport(std::move(Report));
  }

  State = State->set<PointerStateMap>(Sym, PointerState::getReleased());
  C.addTransition(State);
}

void ConditionalOwnershipChecker::checkDeadSymbols(SymbolReaper &SR,
                                                    CheckerContext &C) const {
  ProgramStateRef State = C.getState();
  PointerStateMapTy Tracked = State->get<PointerStateMap>();

  for (auto &E : Tracked) {
    if (SR.isDead(E.first))
      State = State->remove<PointerStateMap>(E.first);
  }
  C.addTransition(State);
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<ConditionalOwnershipChecker>(
      "efa.ConditionalOwnership",
      "Detects double-free from conditional ownership transfer",
      "");
}
