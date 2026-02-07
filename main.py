#!/usr/bin/env python3
"""
Fatih - LLM-driven autonomous penetration testing agent

Main entry point for the Fatih security assessment tool.
This script initializes the orchestrator and runs the autonomous
ReAct loop for penetration testing.

Usage:
    python main.py --target https://example.com
    python main.py --target example.com --max-iterations 10
    python main.py --target https://api.example.com --output outputs/scan_report.json
    python main.py --target example.com --phases recon,http,nmap  # Only run specific phases
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from src.core.orchestrator import Orchestrator
from src.core.state_manager import ALL_PHASES


def setup_logging(log_level: str = "INFO") -> None:
    """Configure logging for the application."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Fatih - Autonomous Penetration Testing Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://example.com
  %(prog)s --target api.example.com --max-iterations 15
  %(prog)s --target https://app.example.com --output reports/scan.json --log-level DEBUG
        """
    )
    
    parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target URL or domain to assess (e.g., https://example.com or example.com)"
    )
    
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=20,
        help="Maximum number of ReAct loop iterations (default: 20)"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="outputs/report.json",
        help="Output path for the final report (default: outputs/report.json)"
    )
    
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)"
    )
    
    parser.add_argument(
        "--phases",
        type=str,
        default=None,
        help=(
            f"Comma-separated list of phases to run (default: all). "
            f"Available phases: {', '.join(ALL_PHASES)}. "
            f"Example: --phases reconnaissance,http_probing,port_scanning"
        )
    )
    
    parser.add_argument(
        "--skip-phases",
        type=str,
        default=None,
        help=(
            f"Comma-separated list of phases to skip. "
            f"Example: --skip-phases directory_fuzzing,vulnerability_scanning"
        )
    )
    
    return parser.parse_args()


def parse_phases(phases_arg: Optional[str], skip_arg: Optional[str]) -> List[str]:
    """Parse --phases and --skip-phases arguments into a list of required phases."""
    if phases_arg:
        # Explicit phases specified
        requested = [p.strip() for p in phases_arg.split(",")]
        return [p for p in requested if p in ALL_PHASES]
    elif skip_arg:
        # Skip specific phases
        to_skip = [p.strip() for p in skip_arg.split(",")]
        return [p for p in ALL_PHASES if p not in to_skip]
    else:
        # Default: all phases
        return ALL_PHASES.copy()


def main() -> int:
    """
    Main entry point for Fatih.
    
    Returns:
        int: Exit code (0 for success, 1 for error)
    """
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    # Parse phases
    required_phases = parse_phases(args.phases, args.skip_phases)
    
    logger.info("=" * 60)
    logger.info("Fatih - Autonomous Penetration Testing Agent")
    logger.info("=" * 60)
    logger.info(f"Target: {args.target}")
    logger.info(f"Max Iterations: {args.max_iterations}")
    logger.info(f"Output: {args.output}")
    logger.info(f"Phases: {', '.join(required_phases)}")
    logger.info("=" * 60)
    
    try:
        # Initialize and run orchestrator
        orchestrator = Orchestrator(
            target_url=args.target,
            max_iterations=args.max_iterations
        )
        
        # Set required phases (if not all)
        if set(required_phases) != set(ALL_PHASES):
            orchestrator.state_manager.set_required_phases(required_phases)
        
        # Run the ReAct loop
        orchestrator.run()
        
        # Export final report
        orchestrator.export_report(args.output)
        
        logger.info("=" * 60)
        logger.info("Assessment completed successfully!")
        logger.info(f"Report saved to: {args.output}")
        logger.info("=" * 60)
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("\nAssessment interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Assessment failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
