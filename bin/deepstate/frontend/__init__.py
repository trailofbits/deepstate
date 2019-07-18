import sys
import pkgutil
import importlib

from .frontend import DeepStateFrontend

def import_fuzzers(pkg_name):
  """
  dynamically load fuzzer frontends using importlib

  TODO(alan): find way to alias modnames so we can check
  them before importing (ie. fuzzer submods need to start with `front_*`)
  """
  package = sys.modules[pkg_name]
  return [
    importlib.import_module(pkg_name + '.' + submod)
    for _, submod, _ in pkgutil.walk_packages(package.__path__)
    #if submod != "frontend"
  ]

__all__ = import_fuzzers(__name__)
