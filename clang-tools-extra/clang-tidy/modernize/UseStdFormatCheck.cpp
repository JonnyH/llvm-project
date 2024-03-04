//===--- UseStdFormatCheck.cpp - clang-tidy-----------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UseStdFormatCheck.h"
#include "../utils/FormatStringConverter.h"
#include "../utils/Matchers.h"
#include "../utils/OptionsUtils.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/FixIt.h"

using namespace clang::ast_matchers;

namespace clang::tidy::modernize {

namespace {
AST_MATCHER(StringLiteral, isOrdinary) { return Node.isOrdinary(); }
} // namespace

UseStdFormatCheck::UseStdFormatCheck(StringRef Name, ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      StrictMode(Options.getLocalOrGlobal("StrictMode", false)),
      SprintfLikeFunctions(utils::options::parseStringList(
          Options.get("SprintfLikeFunctions", ""))),
      ReplacementFormatFunction(
          Options.get("ReplacementFormatFunction", "std::format")),
      IncludeInserter(Options.getLocalOrGlobal("IncludeStyle",
                                               utils::IncludeSorter::IS_LLVM),
                      areDiagsSelfContained()),
      MaybeHeaderToInclude(Options.get("PrintHeader")) {

  if (SprintfLikeFunctions.empty() && SprintfLikeFunctions.empty()) {
    SprintfLikeFunctions.emplace_back("fmt::sprintf");
  }

  if (!MaybeHeaderToInclude && (ReplacementFormatFunction == "std::format"))
    MaybeHeaderToInclude = "<format>";
}

void UseStdFormatCheck::storeOptions(ClangTidyOptions::OptionMap &Opts) {
  using utils::options::serializeStringList;
  Options.store(Opts, "StrictMode", StrictMode);
  Options.store(Opts, "SprintfLikeFunctions",
                serializeStringList(SprintfLikeFunctions));
  Options.store(Opts, "ReplacementFormatFunction", ReplacementFormatFunction);
  Options.store(Opts, "IncludeStyle", IncludeInserter.getStyle());
  if (MaybeHeaderToInclude)
    Options.store(Opts, "PrintHeader", *MaybeHeaderToInclude);
}

void UseStdFormatCheck::registerPPCallbacks(const SourceManager &SM,
                                           Preprocessor *PP,
                                           Preprocessor *ModuleExpanderPP) {
  IncludeInserter.registerPreprocessor(PP);
}

void UseStdFormatCheck::registerMatchers(MatchFinder *Finder) {
  if (!SprintfLikeFunctions.empty())
    Finder->addMatcher(
        
            callExpr(argumentCountAtLeast(1),
                     hasArgument(0, stringLiteral(isOrdinary())),
                     callee(functionDecl(unless(cxxMethodDecl()),
                                         matchers::matchesAnyListedName(
                                             SprintfLikeFunctions))
                                .bind("func_decl")))
                .bind("sprintf"),
        this);
}

void UseStdFormatCheck::check(const MatchFinder::MatchResult &Result) {
  unsigned FormatArgOffset = 0;
  const auto *OldFunction = Result.Nodes.getNodeAs<FunctionDecl>("func_decl");
  const auto *Sprintf = Result.Nodes.getNodeAs<CallExpr>("sprintf");


  utils::FormatStringConverter Converter(
      Result.Context, Sprintf, FormatArgOffset, StrictMode, getLangOpts());
  const Expr *SprintfCall = Sprintf->getCallee();
  const StringRef ReplacementFunction = ReplacementFormatFunction;
  if (!Converter.canApply()) {
    diag(SprintfCall->getBeginLoc(),
         "unable to use '%0' instead of %1 because %2")
        << ReplacementFunction << OldFunction->getIdentifier()
        << Converter.conversionNotPossibleReason();
    return;
  }
  
  if (ReplacementFunction == OldFunction->getIdentifier()->getName())
    return;

  DiagnosticBuilder Diag =
      diag(SprintfCall->getBeginLoc(), "use '%0' instead of %1")
      << ReplacementFunction << OldFunction->getIdentifier();

  Diag << FixItHint::CreateReplacement(
      CharSourceRange::getTokenRange(SprintfCall->getBeginLoc(),
                                     SprintfCall->getEndLoc()),
      ReplacementFunction);
  Converter.applyFixes(Diag, *Result.SourceManager);

  if (MaybeHeaderToInclude)
    Diag << IncludeInserter.createIncludeInsertion(
        Result.Context->getSourceManager().getFileID(SprintfCall->getBeginLoc()),
        *MaybeHeaderToInclude);
}

} // namespace clang::tidy::modernize
