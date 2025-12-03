"""
SSH Guardian 2.0 - Attack Simulation Module
Provides realistic attack simulation and testing capabilities
"""

from .simulator import AttackSimulator
from .templates import ATTACK_TEMPLATES
from .ip_pools import IPPoolManager

__all__ = ['AttackSimulator', 'ATTACK_TEMPLATES', 'IPPoolManager']
