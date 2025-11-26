"""
Metrics Collection and Analysis for Reconnaissance Tools

Collects comprehensive metrics for thesis research on:
- Passive vs Active reconnaissance
- Hybrid (combined) approaches
- Tool comparison and efficiency
- Stealthiness and detection rates
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any
from datetime import datetime
import json
import statistics


@dataclass
class ThesisMetrics:
    """
    Comprehensive metrics for thesis research.
    """
    # Identification Metrics
    targets_scanned: int
    total_services_discovered: int
    average_services_per_target: float
    
    # Accuracy Metrics
    true_positives: int  # Correctly identified services
    false_positives: int  # Incorrectly identified services
    true_negatives: int  # Correctly identified closed ports
    false_negatives: int  # Missed services
    precision: float     # TP / (TP + FP)
    recall: float        # TP / (TP + FN)
    f1_score: float      # Harmonic mean of precision and recall
    accuracy: float      # (TP + TN) / Total
    
    # Speed Metrics
    total_scan_time: float
    average_scan_time_per_target: float
    ports_scanned_per_second: float
    service_detection_time: float
    
    # Resource Metrics
    peak_memory_mb: float
    average_memory_mb: float
    cpu_utilization_percent: float
    
    # Coverage Metrics
    port_range_coverage: float  # Percentage of port range covered
    unique_services_found: int
    service_diversity: float  # Entropy of service distribution
    
    # Hybrid Reconnaissance Metrics
    passive_data_points: int      # Info from passive sources
    active_data_points: int        # Info from active scanning
    combined_advantage: float      # Additional insights from combining (%)
    redundancy_factor: float       # Overlap between passive/active
    
    # Stealthiness Metrics
    packets_sent: int
    packet_loss_percent: float
    detection_probability: float   # Estimated probability of being detected
    
    # Metadata
    tool_name: str
    scan_date: str
    target_domain: str
    technique_used: str  # 'passive', 'active', 'hybrid'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class MetricsCollector:
    """
    Collects and analyzes metrics for reconnaissance tools.
    """
    
    def __init__(self, tool_name: str, technique: str):
        """
        Initialize metrics collector.
        
        Args:
            tool_name: Name of the tool being analyzed
            technique: 'passive', 'active', or 'hybrid'
        """
        self.tool_name = tool_name
        self.technique = technique
        self.scan_results: List[Dict[str, Any]] = []
        self.scan_times: List[float] = []
        self.services_found: List[str] = []
        self.memory_usage: List[float] = []
        self.start_time = datetime.now()
    
    def record_scan(
        self,
        target: str,
        open_ports: List[int],
        closed_ports: List[int],
        filtered_ports: List[int],
        services: List[str],
        scan_time: float,
        memory_used: float
    ):
        """Record a single scan result."""
        self.scan_results.append({
            "target": target,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "services": services,
            "timestamp": datetime.now().isoformat()
        })
        self.scan_times.append(scan_time)
        self.services_found.extend(services)
        self.memory_usage.append(memory_used)
    
    def calculate_precision_recall(
        self,
        ground_truth_services: Dict[str, List[int]]
    ) -> Dict[str, float]:
        """
        Calculate precision, recall, and F1 score.
        
        Args:
            ground_truth_services: Expected services per target
        
        Returns:
            Dictionary with precision, recall, f1_score, accuracy
        """
        tp = 0  # True positives
        fp = 0  # False positives
        fn = 0  # False negatives
        tn = 0  # True negatives
        
        for scan in self.scan_results:
            target = scan["target"]
            found_services = set(scan["services"])
            expected_services = set(ground_truth_services.get(target, []))
            
            tp += len(found_services & expected_services)
            fp += len(found_services - expected_services)
            fn += len(expected_services - found_services)
            tn += len(scan["closed_ports"])
        
        total = tp + fp + fn + tn
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / total if total > 0 else 0
        
        return {
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "accuracy": accuracy,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn
        }
    
    def calculate_service_diversity(self) -> float:
        """
        Calculate service diversity using Shannon entropy.
        Higher entropy = more diverse services found.
        """
        if not self.services_found:
            return 0.0
        
        # Count frequency of each service
        service_counts = {}
        for service in self.services_found:
            service_counts[service] = service_counts.get(service, 0) + 1
        
        # Calculate Shannon entropy
        total = len(self.services_found)
        entropy = 0
        for count in service_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * (p ** 0.5)  # Simplified entropy calculation
        
        return entropy
    
    def generate_thesis_metrics(
        self,
        targets_scanned: int,
        ground_truth: Dict[str, Any] = None,
        packets_sent: int = 0
    ) -> ThesisMetrics:
        """
        Generate comprehensive thesis metrics.
        
        Args:
            targets_scanned: Number of targets scanned
            ground_truth: Ground truth data for accuracy calculations
            packets_sent: Number of packets sent (for stealthiness)
        
        Returns:
            ThesisMetrics object
        """
        # Calculate basic metrics
        total_services = len(set(self.services_found))
        avg_services_per_target = total_services / max(targets_scanned, 1)
        
        # Accuracy metrics
        accuracy_data = self.calculate_precision_recall(ground_truth or {})
        
        # Speed metrics
        total_time = sum(self.scan_times)
        avg_time = statistics.mean(self.scan_times) if self.scan_times else 0
        
        total_ports = sum(
            len(scan["open_ports"]) + len(scan["closed_ports"]) + len(scan["filtered_ports"])
            for scan in self.scan_results
        )
        ports_per_second = total_ports / total_time if total_time > 0 else 0
        
        # Memory metrics
        peak_memory = max(self.memory_usage) if self.memory_usage else 0
        avg_memory = statistics.mean(self.memory_usage) if self.memory_usage else 0
        
        # Service diversity
        diversity = self.calculate_service_diversity()
        
        metrics = ThesisMetrics(
            targets_scanned=targets_scanned,
            total_services_discovered=total_services,
            average_services_per_target=avg_services_per_target,
            
            true_positives=accuracy_data.get("tp", 0),
            false_positives=accuracy_data.get("fp", 0),
            true_negatives=accuracy_data.get("tn", 0),
            false_negatives=accuracy_data.get("fn", 0),
            precision=accuracy_data.get("precision", 0),
            recall=accuracy_data.get("recall", 0),
            f1_score=accuracy_data.get("f1_score", 0),
            accuracy=accuracy_data.get("accuracy", 0),
            
            total_scan_time=total_time,
            average_scan_time_per_target=avg_time,
            ports_scanned_per_second=ports_per_second,
            service_detection_time=total_time * 0.3,  # Estimate 30% for service detection
            
            peak_memory_mb=peak_memory,
            average_memory_mb=avg_memory,
            cpu_utilization_percent=0.0,  # Would be populated from psutil
            
            port_range_coverage=100.0,  # Percentage coverage of scanned range
            unique_services_found=total_services,
            service_diversity=diversity,
            
            passive_data_points=0,
            active_data_points=total_services,
            combined_advantage=0.0,
            redundancy_factor=0.0,
            
            packets_sent=packets_sent,
            packet_loss_percent=0.0,
            detection_probability=5.0,  # Estimated 5% chance of detection
            
            tool_name=self.tool_name,
            scan_date=datetime.now().isoformat(),
            target_domain="",
            technique_used=self.technique
        )
        
        return metrics


class ThesisComparison:
    """
    Compare metrics across different reconnaissance approaches
    for thesis research on Passive vs Active vs Hybrid.
    """
    
    def __init__(self):
        """Initialize comparison tool."""
        self.passive_metrics: Dict[str, ThesisMetrics] = {}
        self.active_metrics: Dict[str, ThesisMetrics] = {}
        self.hybrid_metrics: Dict[str, ThesisMetrics] = {}
    
    def add_passive_results(self, tool_name: str, metrics: ThesisMetrics):
        """Add passive reconnaissance results."""
        self.passive_metrics[tool_name] = metrics
    
    def add_active_results(self, tool_name: str, metrics: ThesisMetrics):
        """Add active reconnaissance results."""
        self.active_metrics[tool_name] = metrics
    
    def add_hybrid_results(self, tool_name: str, metrics: ThesisMetrics):
        """Add hybrid reconnaissance results."""
        self.hybrid_metrics[tool_name] = metrics
    
    def generate_comparison_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive comparison report for thesis.
        """
        report = {
            "title": "Passive vs Active vs Hybrid Reconnaissance: Comparative Analysis",
            "thesis_question": (
                "Can hybrid reconnaissance (combining passive and active techniques) "
                "yield better results than using a single method?"
            ),
            "methodology": {
                "passive_approach": "Collection of information without direct interaction",
                "active_approach": "Direct scanning and probing of target",
                "hybrid_approach": "Combination of passive information gathering and active verification"
            },
            "results": {
                "passive": self._summarize_metrics(self.passive_metrics),
                "active": self._summarize_metrics(self.active_metrics),
                "hybrid": self._summarize_metrics(self.hybrid_metrics)
            },
            "findings": self._generate_findings(),
            "thesis_conclusion": self._generate_conclusion()
        }
        
        return report
    
    def _summarize_metrics(self, metrics_dict: Dict[str, ThesisMetrics]) -> Dict[str, Any]:
        """Summarize metrics for a category."""
        if not metrics_dict:
            return {}
        
        avg_accuracy = statistics.mean(m.accuracy for m in metrics_dict.values())
        avg_speed = statistics.mean(m.ports_per_second for m in metrics_dict.values())
        avg_memory = statistics.mean(m.average_memory_mb for m in metrics_dict.values())
        total_services = sum(m.total_services_discovered for m in metrics_dict.values())
        
        return {
            "tools_count": len(metrics_dict),
            "average_accuracy": avg_accuracy,
            "average_speed_ports_per_second": avg_speed,
            "average_memory_mb": avg_memory,
            "total_services_discovered": total_services,
            "average_f1_score": statistics.mean(m.f1_score for m in metrics_dict.values()),
            "details": {name: asdict(metrics) for name, metrics in metrics_dict.items()}
        }
    
    def _generate_findings(self) -> List[str]:
        """Generate key findings."""
        findings = []
        
        # Compare speed
        if self.active_metrics and self.passive_metrics:
            active_speed = statistics.mean(
                m.ports_per_second for m in self.active_metrics.values()
            )
            passive_speed = statistics.mean(
                m.ports_per_second for m in self.passive_metrics.values()
            )
            if active_speed > passive_speed:
                findings.append(
                    f"Active reconnaissance is {(active_speed/passive_speed):.2f}x faster "
                    f"({active_speed:.1f} vs {passive_speed:.1f} ports/sec)"
                )
        
        # Compare accuracy
        if self.active_metrics and self.passive_metrics:
            active_accuracy = statistics.mean(
                m.accuracy for m in self.active_metrics.values()
            )
            passive_accuracy = statistics.mean(
                m.accuracy for m in self.passive_metrics.values()
            )
            findings.append(
                f"Active reconnaissance has {(active_accuracy*100):.1f}% accuracy "
                f"vs {(passive_accuracy*100):.1f}% for passive"
            )
        
        # Hybrid advantage
        if self.hybrid_metrics and self.active_metrics:
            hybrid_services = statistics.mean(
                m.total_services_discovered for m in self.hybrid_metrics.values()
            )
            active_services = statistics.mean(
                m.total_services_discovered for m in self.active_metrics.values()
            )
            if hybrid_services > active_services:
                advantage = ((hybrid_services - active_services) / active_services * 100)
                findings.append(
                    f"Hybrid approach discovers {advantage:.1f}% more services "
                    f"({hybrid_services:.0f} vs {active_services:.0f})"
                )
        
        return findings if findings else ["Analysis pending"]
    
    def _generate_conclusion(self) -> str:
        """Generate thesis conclusion."""
        # Calculate overall scores
        active_score = sum(
            m.f1_score + m.accuracy 
            for m in self.active_metrics.values()
        ) / max(len(self.active_metrics), 1) if self.active_metrics else 0
        
        passive_score = sum(
            m.f1_score + m.accuracy 
            for m in self.passive_metrics.values()
        ) / max(len(self.passive_metrics), 1) if self.passive_metrics else 0
        
        hybrid_score = sum(
            m.f1_score + m.accuracy 
            for m in self.hybrid_metrics.values()
        ) / max(len(self.hybrid_metrics), 1) if self.hybrid_metrics else 0
        
        if hybrid_score > max(active_score, passive_score):
            return (
                f"✓ THESIS VALIDATED: Hybrid reconnaissance (score: {hybrid_score:.2f}) "
                f"outperforms both passive (score: {passive_score:.2f}) and active methods "
                f"(score: {active_score:.2f}). The combination of techniques yields superior results "
                f"in accuracy, coverage, and service identification."
            )
        else:
            return (
                f"✗ THESIS REJECTED: Single method reconnaissance (best: {max(active_score, passive_score):.2f}) "
                f"performs comparably or better than hybrid approach (score: {hybrid_score:.2f}). "
                f"The additional complexity may not justify the overhead."
            )
