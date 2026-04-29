I'll create a complete implementation for standardizing agent file and custom skill formats for Web3 bug bounty hunting. This will include smart contracts, TypeScript schemas, validation frameworks, and comprehensive documentation.

```typescript
// contracts/AgentRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract AgentRegistry is Ownable, ReentrancyGuard {
    using Counters for Counters.Counter;
    
    Counters.Counter private _agentIds;
    Counters.Counter private _skillIds;
    
    struct Agent {
        uint256 id;
        string name;
        string version;
        address owner;
        string metadataHash;
        string[] skillIds;
        bool isActive;
        uint256 bountyCount;
        uint256 successRate;
        uint256 createdAt;
        uint256 updatedAt;
    }
    
    struct Skill {
        uint256 id;
        string name;
        string category;
        address creator;
        string metadataHash;
        string[] dependencies;
        uint256 usageCount;
        bool isVerified;
        uint256 createdAt;
    }
    
    struct AgentStats {
        uint256 totalBounties;
        uint256 successfulBounties;
        uint256 totalEarnings;
        uint256 reputation;
    }
    
    mapping(uint256 => Agent) public agents;
    mapping(uint256 => Skill) public skills;
    mapping(address => uint256[]) public ownerAgents;
    mapping(address => uint256[]) public creatorSkills;
    mapping(string => bool) public registeredHashes;
    mapping(uint256 => AgentStats) public agentStats;
    mapping(string => uint256) public skillNameToId;
    
    event AgentRegistered(uint256 indexed agentId, string name, address indexed owner);
    event AgentUpdated(uint256 indexed agentId, string version);
    event SkillRegistered(uint256 indexed skillId, string name, address indexed creator);
    event SkillVerified(uint256 indexed skillId, address indexed verifier);
    event AgentDeactivated(uint256 indexed agentId);
    event BountyCompleted(uint256 indexed agentId, bool success, uint256 reward);
    
    modifier onlyAgentOwner(uint256 agentId) {
        require(agents[agentId].owner == msg.sender, "Not agent owner");
        _;
    }
    
    modifier onlySkillCreator(uint256 skillId) {
        require(skills[skillId].creator == msg.sender, "Not skill creator");
        _;
    }
    
    modifier validAgent(uint256 agentId) {
        require(agents[agentId].id != 0, "Agent does not exist");
        _;
    }
    
    modifier validSkill(uint256 skillId) {
        require(skills[skillId].id != 0, "Skill does not exist");
        _;
    }
    
    function registerAgent(
        string memory name,
        string memory version,
        string memory metadataHash,
        string[] memory skillIds
    ) external nonReentrant returns (uint256) {
        require(bytes(name).length > 0, "Agent name required");
        require(bytes(version).length > 0, "Agent version required");
        require(bytes(metadataHash).length > 0, "Metadata hash required");
        require(!registeredHashes[metadataHash], "Metadata hash already registered");
        
        _agentIds.increment();
        uint256 agentId = _agentIds.current();
        
        agents[agentId] = Agent({
            id: agentId,
            name: name,
            version: version,
            owner: msg.sender,
            metadataHash: metadataHash,
            skillIds: skillIds,
            isActive: true,
            bountyCount: 0,
            successRate: 0,
            createdAt: block.timestamp,
            updatedAt: block.timestamp
        });
        
        ownerAgents[msg.sender].push(agentId);
        registeredHashes[metadataHash] = true;
        
        emit AgentRegistered(agentId, name, msg.sender);
        return agentId;
    }
    
    function updateAgent(
        uint256 agentId,
        string memory version,
        string memory metadataHash,
        string[] memory skillIds
    ) external onlyAgentOwner(agentId) validAgent(agentId) {
        require(bytes(version).length > 0, "Version required");
        require(bytes(metadataHash).length > 0, "Metadata hash required");
        
        if (keccak256(bytes(agents[agentId].metadataHash)) != keccak256(bytes(metadataHash))) {
            require(!registeredHashes[metadataHash], "Metadata hash already registered");
            registeredHashes[agents[agentId].metadataHash] = false;
            registeredHashes[metadataHash] = true;
        }
        
        agents[agentId].version = version;
        agents[agentId].metadataHash = metadataHash;
        agents[agentId].skillIds = skillIds;
        agents[agentId].updatedAt = block.timestamp;
        
        emit AgentUpdated(agentId, version);
    }
    
    function registerSkill(
        string memory name,
        string memory category,
        string memory metadataHash,
        string[] memory dependencies
    ) external nonReentrant returns (uint256) {
        require(bytes(name).length > 0, "Skill name required");
        require(bytes(category).length > 0, "Skill category required");
        require(bytes(metadataHash).length > 0, "Metadata hash required");
        require(!registeredHashes[metadataHash], "Metadata hash already registered");
        require(skillNameToId[name] == 0, "Skill name already exists");
        
        _skillIds.increment();
        uint256 skillId = _skillIds.current();
        
        skills[skillId] = Skill({
            id: skillId,
            name: name,
            category: category,
            creator: msg.sender,
            metadataHash: metadataHash,
            dependencies: dependencies,
            usageCount: 0,
            isVerified: false,
            createdAt: block.timestamp
        });
        
        creatorSkills[msg.sender].push(skillId);
        registeredHashes[metadataHash] = true;
        skillNameToId[name] = skillId;
        
        emit SkillRegistered(skillId, name, msg.sender);
        return skillId;
    }
    
    function verifySkill(uint256 skillId) external onlyOwner validSkill(skillId) {
        skills[skillId].isVerified = true;
        emit SkillVerified(skillId, msg.sender);
    }
    
    function deactivateAgent(uint256 agentId) external onlyAgentOwner(agentId) validAgent(agentId) {
        agents[agentId].isActive = false;
        emit AgentDeactivated(agentId);
    }
    
    function recordBountyCompletion(
        uint256 agentId,
        bool success,
        uint256 reward
    ) external onlyOwner validAgent(agentId) {
        agents[agentId].bountyCount++;
        
        AgentStats storage stats = agentStats[agentId];
        stats.totalBounties++;
        stats.totalEarnings += reward;
        
        if (success) {
            stats.successfulBounties++;
            stats.reputation += 10;
        } else {
            stats.reputation = stats.reputation > 5 ? stats.reputation - 5 : 0;
        }
        
        agents[agentId].successRate = (stats.successfulBounties * 100) / stats.totalBounties;
        
        // Update skill usage counts
        for (uint i = 0; i < agents[agentId].skillIds.length; i++) {
            string memory skillName = agents[agentId].skillIds[i];
            uint256 skillId = skillNameToId[skillName];
            if (skillId != 0) {
                skills[skillId].usageCount++;
            }
        }
        
        emit BountyCompleted(agentId, success, reward);
    }
    
    function getAgent(uint256 agentId) external view validAgent(agentId) returns (Agent memory) {
        return agents[agentId];
    }
    
    function getSkill(uint256 skillId) external view validSkill(skillId) returns (Skill memory) {
        return skills[skillId];
    }
    
    function getAgentsByOwner(address owner) external view returns (uint256[] memory) {
        return ownerAgents[owner];
    }
    
    function getSkillsByCreator(address creator) external view returns (uint256[] memory) {
        return creatorSkills[creator];
    }
    
    function getAgentStats(uint256 agentId) external view validAgent(agentId) returns (AgentStats memory) {
        return agentStats[agentId];
    }
    
    function getTotalAgents() external view returns (uint256) {
        return _agentIds.current();
    }
    
    function getTotalSkills() external view returns (uint256) {
        return _skillIds.current();
    }
}
```

```typescript
// src/types/agent.ts
export interface AgentMetadata {
  name: string;
  version: string;
  description: string;
  author: string;
  license: string;
  tags: string[];
  capabilities: AgentCapability[];
  requirements: AgentRequirements;
  skills: string[];
  config: AgentConfig;
  createdAt: string;
  updatedAt: string;
}

export interface AgentCapability {
  id: string;
  name: string;
  description: string;
  category: CapabilityCategory;
  parameters?: CapabilityParameter[];
}

export interface CapabilityParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  required: boolean;
  description: string;
  default?: any;
  validation?: ParameterValidation;
}

export interface ParameterValidation {
  min?: number;
  max?: number;
  pattern?: string;
  enum?: any[];
}

export interface AgentRequirements {
  nodeVersion: string;
  dependencies: Record<string, string>;
  environment: EnvironmentVariable[];
  permissions: Permission[];
}

export interface EnvironmentVariable {
  name: string;
  description: string;
  required: boolean;
  sensitive: boolean;
}

export interface Permission {
  type: 'read' | 'write' | 'execute' | 'network';
  resource: string;
  description: string;
}

export interface AgentConfig {
  maxConcurrency: number;
  timeout: number;
  retries: number;
  logging: LoggingConfig;
  security: SecurityConfig;
}

export interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  output: 'console' | 'file' | 'both';
  maxFileSize?: string;
  maxFiles?: number;
}

export interface SecurityConfig {
  sandboxed: boolean;
  allowedDomains: string[];
  maxMemory: string;
  maxCpu: number;
}

export enum CapabilityCategory {
  WEB3 = 'web3',
  SECURITY = 'security',
  ANALYSIS = 'analysis',
  REPORTING = 'reporting',
  AUTOMATION = 'automation',
  MONITORING = 'monitoring'
}

export interface AgentInstance {
  id: string;
  metadata: AgentMetadata;
  status: AgentStatus;
  stats: AgentStats;
  loadedSkills: LoadedSkill[];
  runtime: RuntimeInfo;
}

export interface AgentStatus {
  state: 'idle' | 'running' | 'paused' | 'error' | 'stopped';
  lastActivity: string;
  currentTask?: string;
  error?: string;
}

export interface AgentStats {
  totalTasks: number;
  successfulTasks: number;
  failedTasks: number;
  averageExecutionTime: number;
  lastExecutionTime: number;
  reputation: number;
  earnings: string; // in Wei
}

export interface LoadedSkill {
  name: string;
  version: string;
  loadedAt: string;
  status: 'loaded' | 'error';
  error?: string;
}

export interface RuntimeInfo {
  pid: number;
  memory: number;
  cpu: number;
  uptime: number;
  nodeVersion: string;
}
```

```typescript
// src/types/skill.ts
export interface SkillMetadata {
  name: string;
  version: string;
  description: string;
  category: SkillCategory;
  author: string;
  license: string;
  tags: string[];
  dependencies: SkillDependency[];
  parameters: SkillParameter[];
  outputs: SkillOutput[];
  examples: SkillExample[];
  documentation: string;
  createdAt: string;
  updatedAt: string;
}

export interface SkillDependency {
  name: string;
  version: string;
  optional: boolean;
  description: string;
}

export interface SkillParameter {
  name: string;
  type: ParameterType;
  required: boolean;
  description: string;
  default?: any;
  validation?: ParameterValidation;
  sensitive?: boolean;
}

export interface SkillOutput {
  name: string;
  type: OutputType;
  description: string;
  schema?: any;
}

export interface SkillExample {
  name: string;
  description: string;
  input: Record<string, any>;
  expectedOutput: any;
}

export enum SkillCategory {
  VULNERABILITY_SCANNING = 'vulnerability-scanning',
  CONTRACT_ANALYSIS = 'contract-analysis',
  TRANSACTION_MONITORING = 'transaction-monitoring',
  DEFI_ANALYSIS = 'defi-analysis',
  NFT_ANALYSIS = 'nft-analysis',
  GOVERNANCE_ANALYSIS = 'governance-analysis',
  ORACLE_ANALYSIS = 'oracle-analysis',
  BRIDGE_ANALYSIS = 'bridge-analysis',
  EXPLOIT_DETECTION = 'exploit-detection',
  REPORTING = 'reporting'
}

export enum ParameterType {
  STRING = 'string',
  NUMBER = 'number',
  BOOLEAN = 'boolean',
  ARRAY = 'array',
  OBJECT = 'object',
  ADDRESS = 'address',
  HASH = 'hash',
  ABI = 'abi',
  BYTECODE = 'bytecode'
}

export enum OutputType {
  REPORT = 'report',
  ALERT = 'alert',
  DATA = 'data',
  FILE = 'file',
  TRANSACTION = 'transaction',
  EVENT = 'event'
}

export interface SkillManifest {
  metadata: SkillMetadata;
  files: SkillFile[];
  entrypoint: string;
  tests: string[];
  assets: