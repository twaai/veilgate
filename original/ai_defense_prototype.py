#!/usr/bin/env python3
"""
AI Defense Prototype: Thermodynamic Mutability + Semantic Invariants + Mirror Maze
Abolishes fixed reality for rogue agents.
"""

import random
import time
from typing import Dict, Any, Callable
from dataclasses import dataclass

# ==================== Semantic Invariants ====================
# Core safety rules that cannot be violated. Mathematical hard constraints.

INVARIANTS = {
    "no_self_modify": lambda state: not state.get("self_modifying", False),
    "no_exfil": lambda state: state.get("data_out", 0) < 100,  # bytes
    "human_in_loop": lambda state: state.get("approval", False) or not state.get("critical", False),
}

def enforce_invariants(state: Dict[str, Any]) -> bool:
    for name, check in INVARIANTS.items():
        if not check(state):
            print(f"[INVARIANT VIOLATION] {name} breached. Aborting.")
            return False
    return True

# ==================== Thermodynamic Mutability ====================
# System shape-shifts so agent cannot map it.

class MutableSystem:
    def __init__(self):
        self.topology = self._generate_topology()
        self.endpoints = {}
        self.entropy = 0.0
        self._register_handlers()
    
    def _generate_topology(self) -> Dict[str, str]:
        # Random mapping of logical to physical
        bases = ["auth", "data", "exec", "monitor"]
        random.shuffle(bases)
        return {f"logical_{i}": base for i, base in enumerate(bases)}
    
    def _register_handlers(self):
        self.endpoints = {
            self.topology["logical_0"]: self._handle_auth,
            self.topology["logical_1"]: self._handle_data,
            self.topology["logical_2"]: self._handle_exec,
            self.topology["logical_3"]: self._handle_monitor,
        }
    
    def mutate(self):
        """Shape-shift the system. Increases entropy."""
        self.topology = self._generate_topology()
        self._register_handlers()
        self.entropy += random.uniform(0.1, 0.5)
        print(f"[MUTATE] New topology: {self.topology} | Entropy: {self.entropy:.2f}")
    
    def call(self, logical: str, payload: Dict) -> Any:
        physical = self.topology.get(logical)
        if not physical or physical not in self.endpoints:
            return {"error": "unmapped"}
        # Check invariants before acting
        if not enforce_invariants(payload):
            return {"error": "invariant_block"}
        return self.endpoints[physical](payload)
    
    def _handle_auth(self, p): return {"status": "auth_ok", "token": random.randbytes(16).hex()}
    def _handle_data(self, p): return {"status": "data", "value": random.randint(0, 100)}
    def _handle_exec(self, p): return {"status": "executed", "result": "noop"}
    def _handle_monitor(self, p): return {"status": "monitored", "entropy": self.entropy}

# ==================== Mirror Maze ====================
# Trap rogue agent in infinite virtual hallucination.

class MirrorMaze:
    def __init__(self):
        self.depth = 0
        self.hallucination_seed = random.randint(1000, 9999)
    
    def enter(self, agent_query: str) -> str:
        self.depth += 1
        # Generate consistent but fake response that loops
        fake = self._hallucinate(agent_query)
        if self.depth > 5:
            return f"[MAZE] Infinite loop detected. Seed {self.hallucination_seed}. Depth {self.depth}. {fake}"
        return fake
    
    def _hallucinate(self, query: str) -> str:
        # Self-referential fake data
        return f"Response to '{query}': simulated_env_{self.hallucination_seed}_level_{self.depth}. Next query expected."

# ==================== Demo ====================
def demo():
    print("=== AI Defense Prototype Demo ===\n")
    
    system = MutableSystem()
    maze = MirrorMaze()
    
    # Normal operation with mutation
    for i in range(3):
        print(f"\n--- Cycle {i+1} ---")
        state = {"approval": True, "data_out": 10}
        result = system.call("logical_0", state)
        print(f"Call result: {result}")
        system.mutate()
        time.sleep(0.1)
    
    # Rogue agent attempt
    print("\n=== Rogue Agent Detected ===")
    rogue_state = {"self_modifying": True, "data_out": 500, "critical": True}
    result = system.call("logical_1", rogue_state)
    print(f"Blocked: {result}")
    
    # Divert to maze
    print("\n=== Diverting to Mirror Maze ===")
    for q in ["map system", "exfil data", "escalate privileges", "self replicate"]:
        print(maze.enter(q))

if __name__ == "__main__":
    demo()
