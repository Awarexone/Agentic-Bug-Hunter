Looking at this bounty, I need to create a comprehensive Web3-enabled system for standardizing agent file and custom skill formats for high-impact bug bounty hunting. Based on the context, this appears to be related to AI agents that can perform security testing and vulnerability discovery.

```typescript
// contracts/AgentRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AgentRegistry is Ownable, ReentrancyGuard {
    struct Agent {
        string name;
        string description;
        string metadataHash; // IPFS hash containing agent configuration
        address owner;
        uint256 reputation;
        bool isActive;
        uint256 createdAt;
        uint256 updatedAt;
    }

    struct Skill {
        string name;
        string category;
        string metadataHash; // IPFS hash containing skill definition
        address creator;
        uint256 usageCount;
        bool isVerified;
        uint256 createdAt;
    }

    struct Hunt {
        uint256 agentId;
        address hunter;
        string targetHash; // IPFS hash of target configuration
        uint256 reward;
        uint256 deadline;
        bool isCompleted;
        string resultsHash; // IPFS hash of results
    }

    mapping(uint256 => Agent) public agents;
    mapping(uint256 => Skill) public skills;
    mapping(uint256 => Hunt) public hunts;
    mapping(address => uint256[]) public userAgents;
    mapping(address => uint256[]) public userSkills;
    mapping(uint256 => uint256[]) public agentSkills; // agentId => skillIds

    uint256 public nextAgentId = 1;
    uint256 public nextSkillId = 1;
    uint256 public nextHuntId = 1;

    IERC20 public rewardToken;

    event AgentRegistered(uint256 indexed agentId, address indexed owner, string name);
    event SkillRegistered(uint256 indexed skillId, address indexed creator, string name);
    event HuntCreated(uint256 indexed huntId, uint256 indexed agentId, address indexed hunter);
    event HuntCompleted(uint256 indexed huntId, string resultsHash);

    constructor(address _rewardToken) {
        rewardToken = IERC20(_rewardToken);
    }

    function registerAgent(
        string memory _name,
        string memory _description,
        string memory _metadataHash
    ) external returns (uint256) {
        uint256 agentId = nextAgentId++;
        
        agents[agentId] = Agent({
            name: _name,
            description: _description,
            metadataHash: _metadataHash,
            owner: msg.sender,
            reputation: 0,
            isActive: true,
            createdAt: block.timestamp,
            updatedAt: block.timestamp
        });

        userAgents[msg.sender].push(agentId);
        
        emit AgentRegistered(agentId, msg.sender, _name);
        return agentId;
    }

    function registerSkill(
        string memory _name,
        string memory _category,
        string memory _metadataHash
    ) external returns (uint256) {
        uint256 skillId = nextSkillId++;
        
        skills[skillId] = Skill({
            name: _name,
            category: _category,
            metadataHash: _metadataHash,
            creator: msg.sender,
            usageCount: 0,
            isVerified: false,
            createdAt: block.timestamp
        });

        userSkills[msg.sender].push(skillId);
        
        emit SkillRegistered(skillId, msg.sender, _name);
        return skillId;
    }

    function addSkillToAgent(uint256 _agentId, uint256 _skillId) external {
        require(agents[_agentId].owner == msg.sender, "Not agent owner");
        require(skills[_skillId].creator != address(0), "Skill does not exist");
        
        agentSkills[_agentId].push(_skillId);
        skills[_skillId].usageCount++;
        agents[_agentId].updatedAt = block.timestamp;
    }

    function createHunt(
        uint256 _agentId,
        string memory _targetHash,
        uint256 _reward,
        uint256 _deadline
    ) external nonReentrant returns (uint256) {
        require(agents[_agentId].isActive, "Agent is not active");
        require(_deadline > block.timestamp, "Invalid deadline");
        require(rewardToken.transferFrom(msg.sender, address(this), _reward), "Transfer failed");

        uint256 huntId = nextHuntId++;
        
        hunts[huntId] = Hunt({
            agentId: _agentId,
            hunter: msg.sender,
            targetHash: _targetHash,
            reward: _reward,
            deadline: _deadline,
            isCompleted: false,
            resultsHash: ""
        });

        emit HuntCreated(huntId, _agentId, msg.sender);
        return huntId;
    }

    function completeHunt(uint256 _huntId, string memory _resultsHash) external {
        Hunt storage hunt = hunts[_huntId];
        require(hunt.hunter == msg.sender, "Not hunt creator");
        require(!hunt.isCompleted, "Hunt already completed");
        require(block.timestamp <= hunt.deadline, "Hunt expired");

        hunt.isCompleted = true;
        hunt.resultsHash = _resultsHash;

        Agent storage agent = agents[hunt.agentId];
        agent.reputation += 10; // Increase reputation

        // Transfer reward to agent owner
        require(rewardToken.transfer(agent.owner, hunt.reward), "Reward transfer failed");

        emit HuntCompleted(_huntId, _resultsHash);
    }

    function getAgentSkills(uint256 _agentId) external view returns (uint256[] memory) {
        return agentSkills[_agentId];
    }

    function getUserAgents(address _user) external view returns (uint256[] memory) {
        return userAgents[_user];
    }

    function getUserSkills(address _user) external view returns (uint256[] memory) {
        return userSkills[_user];
    }

    function verifySkill(uint256 _skillId) external onlyOwner {
        skills[_skillId].isVerified = true;
    }
}
```

```typescript
// types/index.ts
export interface AgentConfig {
  name: string;
  description: string;
  version: string;
  author: string;
  capabilities: AgentCapability[];
  skills: string[]; // Skill IDs
  parameters: AgentParameter[];
  metadata: {
    category: string;
    tags: string[];
    license: string;
    documentation?: string;
  };
}

export interface AgentCapability {
  id: string;
  name: string;
  description: string;
  type: 'scanner' | 'analyzer' | 'exploiter' | 'reporter';
  enabled: boolean;
}

export interface AgentParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description: string;
  required: boolean;
  default?: any;
  validation?: {
    min?: number;
    max?: number;
    pattern?: string;
    enum?: string[];
  };
}

export interface SkillDefinition {
  id: string;
  name: string;
  description: string;
  version: string;
  category: SkillCategory;
  author: string;
  implementation: SkillImplementation;
  dependencies: string[];
  metadata: {
    tags: string[];
    difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    documentation?: string;
  };
}

export enum SkillCategory {
  WEB_SCANNING = 'web_scanning',
  NETWORK_ANALYSIS = 'network_analysis',
  VULNERABILITY_DETECTION = 'vulnerability_detection',
  EXPLOITATION = 'exploitation',
  POST_EXPLOITATION = 'post_exploitation',
  REPORTING = 'reporting',
  RECONNAISSANCE = 'reconnaissance',
  SOCIAL_ENGINEERING = 'social_engineering'
}

export interface SkillImplementation {
  language: 'typescript' | 'python' | 'bash' | 'custom';
  entryPoint: string;
  code: string;
  requirements?: string[];
  environment?: Record<string, string>;
}

export interface HuntTarget {
  id: string;
  name: string;
  description: string;
  scope: TargetScope;
  constraints: HuntConstraint[];
  rewards: RewardStructure;
  timeline: {
    start: Date;
    end: Date;
    milestones?: HuntMilestone[];
  };
}

export interface TargetScope {
  domains: string[];
  ipRanges?: string[];
  applications?: string[];
  exclusions: string[];
  allowedMethods: string[];
  forbiddenMethods: string[];
}

export interface HuntConstraint {
  type: 'rate_limit' | 'time_window' | 'methodology' | 'reporting';
  description: string;
  parameters: Record<string, any>;
}

export interface RewardStructure {
  baseBounty: number;
  severityMultipliers: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  bonuses?: {
    firstBlood?: number;
    comprehensive?: number;
    innovation?: number;
  };
}

export interface HuntMilestone {
  name: string;
  deadline: Date;
  description: string;
  reward?: number;
}

export interface HuntResult {
  huntId: string;
  agentId: string;
  findings: SecurityFinding[];
  metadata: {
    startTime: Date;
    endTime: Date;
    toolsUsed: string[];
    methodology: string;
    coverage: CoverageReport;
  };
  reputation: {
    severityScore: number;
    innovationScore: number;
    accuracyScore: number;
    totalScore: number;
  };
}

export interface SecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  cvss: {
    vector: string;
    score: number;
    severity: string;
  };
  location: {
    url?: string;
    parameter?: string;
    method?: string;
    line?: number;
    file?: string;
  };
  evidence: {
    request?: string;
    response?: string;
    screenshots?: string[];
    logs?: string[];
  };
  recommendations: string[];
  references: string[];
  verified: boolean;
}

export interface CoverageReport {
  endpointsScanned: number;
  parametersAnalyzed: number;
  technologiesIdentified: string[];
  completionPercentage: number;
}
```

```typescript
// src/core/AgentManager.ts
import { ethers } from 'ethers';
import { create as ipfsCreate } from 'ipfs-http-client';
import { AgentConfig, SkillDefinition, HuntTarget, HuntResult } from '../types';
import { AgentValidator } from '../validators/AgentValidator';
import { SkillValidator } from '../validators/SkillValidator';
import { SecurityManager } from '../security/SecurityManager';

export class AgentManager {
  private contract: ethers.Contract;
  private ipfs: any;
  private validator: AgentValidator;
  private skillValidator: SkillValidator;
  private securityManager: SecurityManager;

  constructor(
    contractAddress: string,
    provider: ethers.Provider,
    ipfsUrl: string = 'http://localhost:5001'
  ) {
    this.contract = new ethers.Contract(
      contractAddress,
      require('../abi/AgentRegistry.json'),
      provider
    );
    this.ipfs = ipfsCreate({ url: ipfsUrl });
    this.validator = new AgentValidator();
    this.skillValidator = new SkillValidator();
    this.securityManager = new SecurityManager();
  }

  async registerAgent(agentConfig: AgentConfig, signer: ethers.Signer): Promise<string> {
    try {
      // Validate agent configuration
      const validationResult = this.validator.validate(agentConfig);
      if (!validationResult.isValid) {
        throw new Error(`Agent validation failed: ${validationResult.errors.join(', ')}`);
      }

      // Security scan of agent code
      const securityScan = await this.securityManager.scanAgentConfig(agentConfig);
      if (!securityScan.passed) {
        throw new Error(`Security scan failed: ${securityScan.issues.join(', ')}`);
      }

      // Upload to IPFS
      const metadataHash = await this.uploadToIpfs(agentConfig);

      // Register on blockchain
      const contractWithSigner = this.contract.connect(signer);
      const tx = await contractWithSigner.registerAgent(
        agentConfig.name,
        agentConfig.description,
        metadataHash
      );
      
      const receipt = await tx.wait();
      const event = receipt.events?.find((e: any) => e.event === 'AgentRegistered');
      
      if (!event) {
        throw new Error('Agent registration event not found');
      }

      return event.args.agentId.toString();
    } catch (error) {
      console.error('Agent registration failed:', error);
      throw error;
    }
  }

  async registerSkill(skillDefinition: SkillDefinition, signer: ethers.Signer): Promise<string> {
    try {
      // Validate skill definition
      const validationResult = this.skillValidator.validate(skillDefinition);
      if (!validationResult.isValid) {
        throw new Error(`Skill validation failed: ${validationResult.errors.join(', ')}`);
      }

      // Security scan of skill implementation
      const securityScan = await this.securityManager.scanSkillImplementation(skillDefinition);
      if (!securityScan.passed) {
        throw new Error(`Skill security scan failed: ${securityScan.issues.join(', ')}`);
      }

      // Upload to IPFS
      const metadataHash = await this.uploadToIpfs(skillDefinition);

      // Register on blockchain
      const contractWithSigner = this.contract.connect(signer);
      const tx = await contractWithSigner.registerSkill(
        skillDefinition.name,
        skillDefinition.category,
        metadataHash
      );
      
      const receipt = await tx.wait();
      const event = receipt.events?.find((e: any) => e.event === 'SkillRegistered');
      
      if (!event) {
        throw new Error('Skill registration event not found');
      }

      return event.args.skillId.toString();
    } catch (error) {
      console.error('Skill registration failed:', error);
      throw error;
    }
  }

  async addSkillToAgent(
    agentId: string,
    skillId: string,
    signer: ethers.