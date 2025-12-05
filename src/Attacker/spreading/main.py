"""
Network Spreading Malware Demonstrations
Shows different types of network worms and spreading techniques
⚠️ FOR EDUCATIONAL PURPOSES ONLY ⚠️
"""

import sys
import argparse

# Import demonstration modules
from real_command_execution import demo_real_execution


def demo_command_execution():
    """Demo 1: Real command execution techniques"""
    print("""
╔═══════════════════════════════════════════════════════╗
║  Demo 1: Real Command Execution                      ║
║  Educational Demonstration Only                      ║
╚═══════════════════════════════════════════════════════╝
    """)
    demo_real_execution()


def demo_simple_worm():
    """Demo 2: Simple "Hello World" network worm"""
    print("""
╔═══════════════════════════════════════════════════════╗
║  Demo 2: Simple "Hello World" Network Worm           ║
║  Shows basic network spreading with SSH              ║
╚═══════════════════════════════════════════════════════╝
    """)
    
    # Import and run the simple worm
    from simple_hello_world_worm import SimpleNetworkWorm
    
    print("""
⚠️  WARNING: This will scan and attempt to access systems on your network!

This demonstration will:
1. Scan local network for SSH servers
2. Try common passwords (admin:admin, root:root, etc.)
3. Display "Hello World You've Been Hacked!" on vulnerable machines
4. Copy itself to infected machines for further spreading

ONLY proceed if:
✓ You own ALL machines on the network
✓ You are in an isolated lab environment
✓ You have written authorization
""")
    
    response = input("\nDo you have authorization and are in a lab? (yes/no): ")
    
    if response.lower() != 'yes':
        print("\n✓ Good decision! Exiting demonstration.")
        print("\nStudy the code in 'simple_hello_world_worm.py' to understand:")
        print("  • How worms scan networks")
        print("  • How SSH brute forcing works")
        print("  • How worms self-replicate")
        print("  • How autonomous spreading occurs")
        return
    
    print("\n[*] Starting simple worm demonstration...\n")
    
    # Create and run worm
    worm = SimpleNetworkWorm()
    worm.start()


def demo_advanced_worm():
    """Demo 3: Advanced network worm with full features"""
    print("""
╔═══════════════════════════════════════════════════════╗
║  Demo 3: Advanced Network Worm                       ║
║  Complete attack chain implementation                ║
╚═══════════════════════════════════════════════════════╝
    """)
    
    # Import and run the advanced worm
    from HACKER_IMPLEMENTATION_GUIDE import RealNetworkWorm
    
    print("""
⚠️⚠️⚠️ CRITICAL WARNING ⚠️⚠️⚠️

This is a COMPLETE network worm with:
• Network scanning
• Credential brute forcing
• Remote code execution
• Data exfiltration
• Persistence installation
• Lateral movement
• Command & Control

This is REAL MALWARE! Only use in authorized isolated lab.
""")
    
    response = input("\nProceed with advanced worm demo? (yes/no): ")
    
    if response.lower() != 'yes':
        print("\n✓ Exiting. Study the code in 'HACKER_IMPLEMENTATION_GUIDE.py'")
        return
    
    response = input("\nConfirm you have WRITTEN authorization? (yes/no): ")
    
    if response.lower() != 'yes':
        print("\n❌ Authorization required. Exiting.")
        return
    
    print("\n[*] Starting advanced worm demonstration...\n")
    
    # Create and run worm
    worm = RealNetworkWorm()
    worm.run()


def list_demos():
    """Show available demonstrations"""
    print("""
╔═══════════════════════════════════════════════════════╗
║  Available Demonstrations                            ║
╚═══════════════════════════════════════════════════════╝

1. command-execution
   └─ Shows real SSH/WMI command execution techniques
   └─ Safe: Only affects YOUR machine (shows notification)
   └─ File: real_command_execution.py

2. simple-worm
   └─ Simple "Hello World" network worm
   └─ Spreads via SSH, displays message on victims
   └─ File: simple_hello_world_worm.py
   └─ ⚠️  Requires: Isolated lab environment

3. advanced-worm
   └─ Complete network worm with all features
   └─ Full attack chain: scan, exploit, persist, spread
   └─ File: HACKER_IMPLEMENTATION_GUIDE.py
   └─ ⚠️⚠️  Requires: Written authorization + isolated lab

Usage:
  python3 main.py --demo <name>

Examples:
  python3 main.py --demo command-execution
  python3 main.py --demo simple-worm
  python3 main.py --demo advanced-worm
  python3 main.py --list
""")


def main():
    """Main execution point with demo selection"""
    parser = argparse.ArgumentParser(
        description="Network Spreading Malware Demonstrations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show available demos
  python3 main.py --list
  
  # Run command execution demo (safe)
  python3 main.py --demo command-execution
  
  # Run simple worm demo (requires lab)
  python3 main.py --demo simple-worm
  
  # Run advanced worm demo (requires authorization)
  python3 main.py --demo advanced-worm
        """
    )
    
    parser.add_argument(
        '--demo',
        choices=['command-execution', 'simple-worm', 'advanced-worm'],
        help='Select demonstration to run'
    )
    
    parser.add_argument(
        '--list',
        action='store_true',
        help='List all available demonstrations'
    )
    
    args = parser.parse_args()
    
    try:
        if args.list:
            list_demos()
        elif args.demo == 'command-execution':
            demo_command_execution()
        elif args.demo == 'simple-worm':
            demo_simple_worm()
        elif args.demo == 'advanced-worm':
            demo_advanced_worm()
        else:
            # No arguments provided, show help
            parser.print_help()
            print("\n💡 Tip: Use --list to see all available demonstrations")
    
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()