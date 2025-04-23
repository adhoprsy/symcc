// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

#include "Pass.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/CodeGen/IntrinsicLowering.h>
#include <llvm/CodeGen/TargetLowering.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <filesystem>

#if LLVM_VERSION_MAJOR < 14
#include <llvm/Support/TargetRegistry.h>
#else
#include <llvm/MC/TargetRegistry.h>
#endif

#include "Runtime.h"
#include "Symbolizer.h"

using namespace llvm;

#ifndef NDEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

#define MAP_SIZE (1<<18)

uint32_t read_id_from_metadata(MDNode* MD) {
  if (MD && MD->getNumOperands() >= 1) {
    if (ConstantInt *CI = mdconst::dyn_extract<ConstantInt>(MD->getOperand(0))) {
      uint64_t id = CI->getZExtValue();
      return id;
    }
  }
  return 0;
}

std::string get_function_filename(const Function &F) {
    if (DISubprogram *SP = F.getSubprogram()) {
        if (DIFile *File = SP->getFile()) {
          auto path = std::filesystem::path(File->getFilename().str());
          return path.filename().string();
        }
    }
    return "";
}

std::string generate_bb_hash_single(const BasicBlock* BB) {
  std::string BBContent;
  raw_string_ostream os(BBContent);
  for (const auto& I : *BB) {
    if (auto* intrinsin = llvm::dyn_cast<llvm::IntrinsicInst>(&I)) {
      continue;
    }
    os << I.getOpcode();
    for (Value* op: I.operands())
      if (op->getType()) {
        op->getType()->print(os);
        if (op->hasName()) os << op->getName();
        else if (isa<Constant>(op)) os << *op;
        os << "|";
      }
  }
  // function name
  os << BB->getParent()->getName();
  // file name
  os << get_function_filename(*BB->getParent());

  return os.str();
}

uint32_t generate_bb_hash(const BasicBlock* BB) {
  std::string BBContent;
  raw_string_ostream os(BBContent);

  os << generate_bb_hash_single(BB) << "$$";
  if(!pred_empty(BB)) {
    for (const BasicBlock* pred: predecessors(BB)) {
      os << generate_bb_hash_single(pred) << "$$";
    }
  }

  auto* term = BB->getTerminator();
  if (term->getNumSuccessors() > 0) {
    for (const BasicBlock* succ: successors(BB)) {
      os << generate_bb_hash_single(succ) << "$$";
    }
  }

  // errs() << "=======================\n";
  // errs() << os.str() << "\n";
  // errs() << "=======================\n";
  std::hash<std::string> hasher;
  return static_cast<uint32_t>(hasher(os.str()) % MAP_SIZE );
}

char SymbolizeLegacyPass::ID = 0;

namespace {

static constexpr char kSymCtorName[] = "__sym_ctor";

bool instrumentModule(Module &M) {
  DEBUG(errs() << "Symbolizer module instrumentation\n");

  // Redirect calls to external functions to the corresponding wrappers and
  // rename internal functions.
  for (auto &function : M.functions()) {
    auto name = function.getName();
    if (isInterceptedFunction(function))
      function.setName(name + "_symbolized");
  }

  // Insert a constructor that initializes the runtime and any globals.
  Function *ctor;
  std::tie(ctor, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, kSymCtorName, "_sym_initialize", {}, {});
  appendToGlobalCtors(M, ctor, 0);

  return true;
}

bool canLower(const CallInst *CI) {
  const Function *Callee = CI->getCalledFunction();
  if (!Callee)
    return false;

  switch (Callee->getIntrinsicID()) {
  case Intrinsic::expect:
  case Intrinsic::ctpop:
  case Intrinsic::ctlz:
  case Intrinsic::cttz:
  case Intrinsic::prefetch:
  case Intrinsic::pcmarker:
  case Intrinsic::dbg_declare:
  case Intrinsic::dbg_label:
  case Intrinsic::eh_typeid_for:
  case Intrinsic::annotation:
  case Intrinsic::ptr_annotation:
  case Intrinsic::assume:
#if LLVM_VERSION_MAJOR > 11
  case Intrinsic::experimental_noalias_scope_decl:
#endif
  case Intrinsic::var_annotation:
  case Intrinsic::sqrt:
  case Intrinsic::log:
  case Intrinsic::log2:
  case Intrinsic::log10:
  case Intrinsic::exp:
  case Intrinsic::exp2:
  case Intrinsic::pow:
  case Intrinsic::sin:
  case Intrinsic::cos:
  case Intrinsic::floor:
  case Intrinsic::ceil:
  case Intrinsic::trunc:
  case Intrinsic::round:
#if LLVM_VERSION_MAJOR > 10
  case Intrinsic::roundeven:
#endif
  case Intrinsic::copysign:
#if LLVM_VERSION_MAJOR < 16
  case Intrinsic::flt_rounds:
#else
  case Intrinsic::get_rounding:
#endif
  case Intrinsic::invariant_start:
  case Intrinsic::lifetime_start:
  case Intrinsic::invariant_end:
  case Intrinsic::lifetime_end:
    return true;
  default:
    return false;
  }

  llvm_unreachable("Control cannot reach here");
}

void liftInlineAssembly(CallInst *CI) {
  // TODO When we don't have to worry about the old pass manager anymore, move
  // the initialization to the pass constructor. (Currently there are two
  // passes, but only if we're on a recent enough LLVM...)

  Function *F = CI->getFunction();
  Module *M = F->getParent();
  auto triple = M->getTargetTriple();

  std::string error;
  auto target = TargetRegistry::lookupTarget(triple, error);
  if (!target) {
    errs() << "Warning: can't get target info to lift inline assembly\n";
    return;
  }

  auto cpu = F->getFnAttribute("target-cpu").getValueAsString();
  auto features = F->getFnAttribute("target-features").getValueAsString();

  std::unique_ptr<TargetMachine> TM(
      target->createTargetMachine(triple, cpu, features, TargetOptions(), {}));
  auto subTarget = TM->getSubtargetImpl(*F);
  if (subTarget == nullptr)
    return;

  auto targetLowering = subTarget->getTargetLowering();
  if (targetLowering == nullptr)
    return;

  targetLowering->ExpandInlineAsm(CI);
}

bool instrumentFunction(Function &F) {
  auto functionName = F.getName();
  if (functionName == kSymCtorName)
    return false;

  DEBUG(errs() << "Symbolizing function ");
  DEBUG(errs().write_escaped(functionName) << '\n');

  SmallVector<Instruction *, 0> allInstructions;
  allInstructions.reserve(F.getInstructionCount());
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  IntrinsicLowering IL(F.getParent()->getDataLayout());
  for (auto *I : allInstructions) {
    if (auto *CI = dyn_cast<CallInst>(I)) {
      if (canLower(CI)) {
        IL.LowerIntrinsicCall(CI);
      } else if (isa<InlineAsm>(CI->getCalledOperand())) {
        liftInlineAssembly(CI);
      }
    }
  }

  allInstructions.clear();
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  Symbolizer symbolizer(*F.getParent());
  symbolizer.symbolizeFunctionArguments(F);

  for (auto &basicBlock : F)
    symbolizer.insertBasicBlockNotification(basicBlock);

  for (auto *instPtr : allInstructions)
    symbolizer.visit(instPtr);

  symbolizer.finalizePHINodes();
  symbolizer.shortCircuitExpressionUses();

  // DEBUG(errs() << F << '\n');
  assert(!verifyFunction(F, &errs()) &&
         "SymbolizePass produced invalid bitcode");

  return true;
}

PreservedAnalyses uniqueidmodule(Module &M) {
  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F) {
      Instruction* terminator = BB.getTerminator();
      if (!terminator) continue;

      // branch instructions
      const BranchInst* br = dyn_cast<BranchInst>(terminator);
      if (br && br->isConditional()) {

        auto IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (!terminator->hasMetadata(M.getMDKindID("basicblock.id"))) {
          // uint64_t raw_id = distr(gen);
          uint32_t raw_id = generate_bb_hash(&BB);
          MDNode* node =  MDNode::get(BB.getContext(), ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(BB.getContext()), raw_id)));
          terminator->setMetadata(M.getMDKindID("basicblock.id"), node);
          inst_blocks++;
        }

        // uint32_t parent_id =read_id_from_metadata(terminator->getMetadata(M.getMDKindID("basicblock.id")));
        // errs() << "-----------------------------------------------\n";
        // errs() << BB << "\n";
        // errs() << "bb_id: " <<BB.getName() << " | unique_id: " <<parent_id << " | " <<*terminator << "\n";
        // assign id for its child
        for (BasicBlock* succ: successors(&BB)) {
          Instruction* term = succ->getTerminator();
          if (!term) continue;
          auto IP = succ->getFirstInsertionPt();
          IRBuilder<> IRB(&(*IP));
          if (!term->hasMetadata(M.getMDKindID("basicblock.id"))) {
            // uint64_t raw_id = distr(gen);
            uint32_t raw_id = generate_bb_hash(succ);
            MDNode* node =  MDNode::get(BB.getContext(), ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(BB.getContext()), raw_id)));
            term->setMetadata(M.getMDKindID("basicblock.id"), node);
            inst_blocks++;
          }
          // uint32_t child_id = read_id_from_metadata(term->getMetadata(M.getMDKindID("basicblock.id")));

          // errs() << "child: " << *succ << "\n";
          // errs() << "child : " <<child_id << " | " <<*term << "\n\n";

        }
      }

      // switch instructions
      const SwitchInst* sw = dyn_cast<SwitchInst>(terminator);
      if (sw) {
        auto IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (!terminator->hasMetadata(M.getMDKindID("basicblock.id"))) {
          // uint64_t raw_id = distr(gen);
          uint32_t raw_id = generate_bb_hash(&BB);
          MDNode* node =  MDNode::get(BB.getContext(), ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(BB.getContext()), raw_id)));
          terminator->setMetadata(M.getMDKindID("basicblock.id"), node);
          inst_blocks++;
        }
        // uint64_t parent_id =read_id_from_metadata(terminator->getMetadata(M.getMDKindID("basicblock.id")));
        // assign id for its child
        for (BasicBlock* succ: successors(&BB)) {
          Instruction* term = succ->getTerminator();
          if (!term) continue;
          auto IP = succ->getFirstInsertionPt();
          IRBuilder<> IRB(&(*IP));
          if (!term->hasMetadata(M.getMDKindID("basicblock.id"))) {
            // uint64_t raw_id = distr(gen);
            uint32_t raw_id = generate_bb_hash(succ);
            // childs_map[parent_id].insert(raw_id);
            MDNode* node =  MDNode::get(BB.getContext(), ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(BB.getContext()), raw_id)));
            term->setMetadata(M.getMDKindID("basicblock.id"), node);
            inst_blocks++;
          }
        }
      }
    }

  errs() << "Unique ID Pass instrumented blocks : " << inst_blocks << "\n";

  return PreservedAnalyses();
}

} // namespace

bool SymbolizeLegacyPass::doInitialization(Module &M) {
  return instrumentModule(M);
}

bool SymbolizeLegacyPass::runOnFunction(Function &F) {
  return instrumentFunction(F);
}

#if LLVM_VERSION_MAJOR >= 13

PreservedAnalyses SymbolizePass::run(Function &F, FunctionAnalysisManager &) {
  return instrumentFunction(F) ? PreservedAnalyses::none()
                               : PreservedAnalyses::all();
}

PreservedAnalyses SymbolizePass::run(Module &M, ModuleAnalysisManager &) {
  return instrumentModule(M) ? PreservedAnalyses::none()
                             : PreservedAnalyses::all();
}

PreservedAnalyses UniqueID::run(Module &M, ModuleAnalysisManager &) {
  return uniqueidmodule(M);
}

#endif
