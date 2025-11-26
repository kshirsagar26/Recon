"""
Testing script for the port scanning module.
Run this to validate your custom scanner implementation.
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_path))

from app.modules.port_scan.engine import PortScanner, COMMON_PORTS
from app.modules.port_scan.benchmark import BenchmarkSuite, compare_hybrid_vs_single
from app.modules.port_scan.metrics import MetricsCollector, ThesisComparison


async def test_single_host_scan():
    """Test scanning a single host."""
    print("\n" + "="*60)
    print("TEST 1: Single Host Scanning")
    print("="*60)
    
    scanner = PortScanner(timeout=3.0)
    
    # Scan localhost
    print("\nScanning localhost (127.0.0.1)...")
    results, metrics = await scanner.scan_common_ports("127.0.0.1")
    
    print(f"\n✓ Scan Complete")
    print(f"  • Ports scanned: {metrics.total_ports_scanned}")
    print(f"  • Open ports: {metrics.open_ports_found}")
    print(f"  • Closed ports: {metrics.closed_ports}")
    print(f"  • Filtered ports: {metrics.filtered_ports}")
    print(f"  • Total time: {metrics.total_time:.2f}s")
    print(f"  • Speed: {metrics.ports_per_second:.1f} ports/sec")
    print(f"  • Avg response time: {metrics.average_response_time:.3f}s")
    
    if results:
        print("\n  Open ports found:")
        for r in results:
            if r.status == "open":
                print(f"    • {r.port}/{r.service} - {r.banner[:50] if r.banner else 'N/A'}")


async def test_port_range_scan():
    """Test scanning a specific port range."""
    print("\n" + "="*60)
    print("TEST 2: Port Range Scanning")
    print("="*60)
    
    scanner = PortScanner(timeout=2.0)
    
    # Scan common ports on localhost
    print("\nScanning ports 1-100 on localhost...")
    results, metrics = await scanner.scan_port_range(
        "127.0.0.1",
        start_port=1,
        end_port=100,
        use_common_ports=True
    )
    
    print(f"\n✓ Scan Complete")
    print(f"  • Ports scanned: {metrics.total_ports_scanned}")
    print(f"  • Open ports: {metrics.open_ports_found}")
    print(f"  • Speed: {metrics.ports_per_second:.1f} ports/sec")
    print(f"  • Total time: {metrics.total_time:.2f}s")


async def test_hybrid_vs_single():
    """Test hybrid vs single method comparison."""
    print("\n" + "="*60)
    print("TEST 3: Hybrid vs Single Method Comparison")
    print("="*60)
    
    comparison = await compare_hybrid_vs_single("127.0.0.1")
    
    print(f"\nSingle Method Results:")
    print(f"  • Technique: {comparison['single_method']['technique']}")
    print(f"  • Time: {comparison['single_method']['time']:.2f}s")
    print(f"  • Open ports: {comparison['single_method']['open_ports']}")
    print(f"  • Ports scanned: {comparison['single_method']['ports_scanned']}")
    
    print(f"\nHybrid Method Results:")
    print(f"  • Technique: {comparison['hybrid_method']['technique']}")
    print(f"  • Time: {comparison['hybrid_method']['time']:.2f}s")
    print(f"  • Open ports: {comparison['hybrid_method']['open_ports']}")
    print(f"  • Services identified: {comparison['hybrid_method'].get('services_identified', 0)}")
    
    print(f"\nComparison:")
    print(f"  • Extra time needed: {comparison['comparison']['time_difference']['extra_time_for_hybrid']:.2f}s")
    print(f"  • Time increase: {comparison['comparison']['time_difference']['time_increase_percent']:.1f}%")
    print(f"  • Additional insights: {comparison['comparison']['additional_insight_from_hybrid']['extra_context']}")
    
    print(f"\n📊 THESIS FINDING:")
    print(comparison['thesis_finding'])


async def test_metrics_collection():
    """Test metrics collection."""
    print("\n" + "="*60)
    print("TEST 4: Metrics Collection")
    print("="*60)
    
    collector = MetricsCollector("Custom Scanner", "active")
    
    # Simulate some scan results
    print("\nSimulating scan results...")
    collector.record_scan(
        target="example.com",
        open_ports=[80, 443, 8080],
        closed_ports=[21, 23, 25],
        filtered_ports=[1, 2, 3],
        services=["HTTP", "HTTPS", "HTTP-Alt"],
        scan_time=2.5,
        memory_used=150.0
    )
    
    collector.record_scan(
        target="test.example.com",
        open_ports=[80, 443],
        closed_ports=[21, 23, 25],
        filtered_ports=[1, 2, 3],
        services=["HTTP", "HTTPS"],
        scan_time=1.8,
        memory_used=120.0
    )
    
    metrics = collector.generate_thesis_metrics(targets_scanned=2)
    
    print(f"\n✓ Metrics Generated:")
    print(f"  • Targets scanned: {metrics.targets_scanned}")
    print(f"  • Services discovered: {metrics.total_services_discovered}")
    print(f"  • Avg services/target: {metrics.average_services_per_target:.1f}")
    print(f"  • Total scan time: {metrics.total_scan_time:.2f}s")
    print(f"  • Speed: {metrics.ports_per_second:.1f} ports/sec")
    print(f"  • Peak memory: {metrics.peak_memory_mb:.1f} MB")


def test_benchmark_suite():
    """Test benchmark suite setup."""
    print("\n" + "="*60)
    print("TEST 5: Benchmark Suite")
    print("="*60)
    
    benchmark = BenchmarkSuite(target_host="127.0.0.1")
    
    print("\n✓ Benchmark suite initialized")
    print(f"  • Target: 127.0.0.1")
    print(f"  • Nmap available: {benchmark._check_nmap_installed()}")
    print(f"  • Masscan available: {benchmark._check_masscan_installed()}")
    
    print("\nNote: Full benchmark requires Nmap/Masscan to be installed.")
    print("To run full benchmark:")
    print("  1. Install Nmap: https://nmap.org/download.html")
    print("  2. Install Masscan: https://github.com/robertdavidgraham/masscan")
    print("  3. Call: await benchmark.run_comprehensive_benchmark()")


async def main():
    """Run all tests."""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + " CUSTOM PORT SCANNER - THESIS TESTING SUITE ".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "="*58 + "╝")
    
    try:
        # Run tests
        await test_single_host_scan()
        await test_port_range_scan()
        await test_hybrid_vs_single()
        await test_metrics_collection()
        test_benchmark_suite()
        
        print("\n" + "="*60)
        print("ALL TESTS COMPLETED SUCCESSFULLY ✓")
        print("="*60)
        
        print("\n📚 Next Steps for Thesis:")
        print("  1. Run full benchmark against real targets")
        print("  2. Collect metrics from multiple scans")
        print("  3. Compare with Nmap/Masscan results")
        print("  4. Validate hybrid > single method hypothesis")
        print("  5. Document findings in thesis paper")
        
    except Exception as e:
        print(f"\n✗ Test Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
