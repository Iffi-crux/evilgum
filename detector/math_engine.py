import math
from typing import List, Tuple

class VectorMath:
    """
    Detector Math Engine: V4 Patch
    Provides floating-point resilient statistical accumulation for high-dimensional embeddings.
    """

    @staticmethod
    def l2_norm_clip(vector: List[float], max_norm: float = 1.0) -> List[float]:
        """
        Calculates the L2 norm of the vector and scales it down if it exceeds max_norm.
        This prevents adversarial embeddings with extreme magnitude from blowing up the accumulator.
        """
        l2_norm = math.sqrt(sum(x * x for x in vector))
        
        if l2_norm <= max_norm or l2_norm == 0.0:
            return vector
            
        scale_factor = max_norm / l2_norm
        return [x * scale_factor for x in vector]

class KahanWelfordAccumulator:
    """
    Kahan-Compensated Welford Algorithm.
    Eliminates catastrophic floating-point cancellation when calculating 
    running variance for extreme-magnitude adversarial embeddings.
    """
    def __init__(self, dimensions: int):
        self.n: int = 0
        self.mean: List[float] = [0.0] * dimensions
        self.m2: List[float] = [0.0] * dimensions
        
        # Kahan compensation accumulators for mean and M2 to track lost low-order bits
        self._mean_c: List[float] = [0.0] * dimensions
        self._m2_c: List[float] = [0.0] * dimensions

    def update(self, vector: List[float]):
        """
        Updates the running mean and variance using a Kahan-compensated Welford step.
        """
        if len(vector) != len(self.mean):
            raise ValueError("Input vector dimensions do not match accumulator dimensions.")
            
        self.n += 1

        for i in range(len(vector)):
            x = vector[i]
            
            # 1. Update Mean with Kahan Summation
            delta = x - self.mean[i]
            mean_update = delta / self.n
            
            # Kahan summation step for mean
            y_mean = mean_update - self._mean_c[i]
            t_mean = self.mean[i] + y_mean
            self._mean_c[i] = (t_mean - self.mean[i]) - y_mean
            self.mean[i] = t_mean
            
            # 2. Update M2 with Kahan Summation
            delta2 = x - self.mean[i]
            m2_update = delta * delta2
            
            # Kahan summation step for M2
            y_m2 = m2_update - self._m2_c[i]
            t_m2 = self.m2[i] + y_m2
            self._m2_c[i] = (t_m2 - self.m2[i]) - y_m2
            self.m2[i] = t_m2

    def variance(self) -> List[float]:
        """Returns the population variance for each dimension."""
        if self.n < 1:
            return [0.0] * len(self.mean)
        return [m / self.n for m in self.m2]

    def sample_variance(self) -> List[float]:
        """Returns the sample variance for each dimension."""
        if self.n < 2:
            return [0.0] * len(self.mean)
        return [m / (self.n - 1) for m in self.m2]
