"""Entry-point target for the inspect_ai hook group. Importing this module registers ProofbundleHooks as an
import side-effect. Kept intentionally minimal (no crypto) so inspect's startup discovery stays fast."""
from .inspect_hook import ProofbundleHooks  # noqa: F401 — import side-effect registers the hook
