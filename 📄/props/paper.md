# Props for Machine-Learning Security

## Paper Metadata
- **arXiv:** 2410.20522v1
- **Date:** October 27, 2024
- **Authors:** Ari Juels (Cornell Tech), Farinaz Koushanfar (University of California San Diego)
- **Source PDF:** https://arxiv.org/pdf/2410.20522
- **Source HTML:** https://arxiv.org/html/2410.20522

---

## Abstract

We propose protected pipelines or props for short, a new approach for authenticated, privacy-preserving access to deep-web data for machine learning (ML). By permitting secure use of vast sources of deep-web data, props address the systemic bottleneck of limited high-quality training data in ML development. Props also enable privacy-preserving and trustworthy forms of inference, allowing for safe use of sensitive data in ML applications. Finally, props offer a new approach to constraining adversarial inputs. Props are practically realizable today by leveraging privacy-preserving oracle systems initially developed for blockchain applications.

---

## 1 Introduction

There’s only one World Wide Web (WWW). This simple fact represents a major barrier for advances in machine learning, as practitioners are reaching fundamental limits in available data sources for model training [19, 37]. They’re relying increasingly instead on synthetic data, a partial remedy that carries the risk of training models that are self-poisoned or misrepresent the real world [24]. Practitioners are also making efforts to tap private sources of data. Obtaining access to sensitive sources of data, though, often requires legally complex and labor-intensive negotiations over conditions of use and subjects large populations of users to the risk of privacy breaches.

Fortunately, there is more than one WWW. There is the surface web, with its publicly accessible, indexed data. Then there is the deep web. The deep web—meaning data sources walled-off from scraping, and ranging from legitimate consumer and enterprise environments to (dark-web) sites of illicit activity—is estimated to be two orders of magnitude larger than the surface public web [3, 29].

Deep-web data can include personal data such as e-mail, health or fitness data from personal devices or medical providers, e-mail, digital calendars, photographs, and financial statements. It can also include documents maintained by organizations, including billing and accounting data, customer orders, transaction records and so forth. As we explain, little of such data can be shared securely with today’s web infrastructure, greatly limiting its availability for ML applications.

In this short work, we propose a new idea that we call protected pipelines for machine learning security or props for short. Props enable secure access to deep web data. The security assurances that props provide—which include both integrity and privacy—also give rise to both new security models for ML applications and new models of data sharing for end users. Critically, props do not require any modification to existing web infrastructure.

We give an overview of props in Section 2, along with examples to illustrate their applications. In Section 3, we explain how they can be built using privacy-preserving oracles designed for blockchain systems. We summarize our ideas in Section 4. Our examples focus on private user data, as secure sharing of such data is especially challenging given today’s web infrastructure.

## 2 What Are Props?

Props are a data pipeline extending from deep-web data sources to points of use in the ML ecosystem. They enforce two key security properties.

The first property of props is privacy, specifically the ability of a user to retain control over disclosure of data throughout the pipeline. Props may be viewed as enforcing a common notion of privacy known as “contextual integrity,” meaning that data flows appropriately according to its intended use [2, 25]. Props in particular ensure that data remain confidential in the greatest degree that is consistent with their use in target applications.

The second property of props is integrity, meaning specifically that props prove to consumers of deep-web data and users of downstream models relying on these data that the data are authentic, i.e., come from trustworthy deep-web sources.

Props can support both model training and inference.

### 2.1 Props for model training

Here is an illustration of the use of props for model training.

##### Example 1 (Training: Health data).

MediModels Inc. is training a health-diagnostics ML model. Alice wishes to furnish her electronic health record (EHR) as training data for the model.

Alice could just download her EHR—let’s denote it by X—from her medical provider BigHospital (e.g., as a PDF) and send it to MediModels. But then MediModels would have no way to ensure that X is real, i.e., not modified or fabricated by Alice. Fake data from malicious users (or competitors) could irremediably corrupt MediModel’s model.

Alice can instead use an app, provided by MediModels, that realizes a prop for ML. This app enables Alice to log into the web portal of BigHospital, obtain her EHR, and then relay her EHR to MediModels.

MediModels obtains high assurance that X is authentic: it is the result of Alice sourcing her EHR from BigHospital. Alice consents to and controls release of her information. Critically here, in our proposed approach BigHospital need not modify its web servers or even know of the use or existence of MediModels’ app.

Props are compatible with privacy-preserving ML training systems, such as federated learning [15] or use of trusted execution environments [23]. In Example 1, if MediModels is using such a system, Alice’s data would never be disclosed explicitly to MediModels or anyone else. It would only serve for model training. [Footnote 1: There is significant literature on the extraction of training data from models (see, e.g., [22, 31]), so caution is still needed even when the process of model training itself operates on confidential inputs.]

**Figure 1: Illustration of Example 1. Alice obtains her EHR X from BigHospital and relays it to MediModels. A prop proof shows that X is authentic, the result of Alice querying BigHospital’s web portal for her EHR.**

### 2.2 Props for inference

Props can also support pipelines for ML inference. In this case, a prop proves that an inference results from applying a particular model to authenticated, sensitive source data—without directly revealing the data. In other words, it provides precise provenance for an inference result. Example 2 illustrates this idea. We use the informal notation M(X) to denote the application of a model M to source data X.

##### Example 2 (Inference: Privacy-preserving loan decision).

Bob applies for a loan from a new financial services company called PrivaLoan. PrivaLoan has an innovative approach to lending. Bob obtains a set X of trustworthy financial documents (e.g., transaction statements) from any of a range of pre-approved sources (major banks and brokerage firms) on the web, e.g., BigBank. He then uses a prop-enabled PrivaLoan app to: (1) Execute a PrivaLoan loan-decision model M on X on his own mobile phone, resulting in loan decision Y and then (2) Generate a proof showing that Y=M(X) for X a set of validly sourced documents. PrivaLoan then acts on decision Y. Figure 2 illustrates this prop inference scenario.

**Figure 2: Illustration of Example 2. Bob obtains a financial document X from BigBank. He runs model M on it and sends the output Y to PrivaLoan. A prop proof shows that Y=M(X) for an authentic document X.**

This example illustrates how a consumer can use sensitive data privately to support organizations’ decision-making. Such privacy-preserving inference is not just of benefit to users, but also enables organizations to avoid the risks of handling sensitive consumer data and could position stakeholders to align with or even set the standards for privacy-first ML applications in order to meet regulations such as HIPAA and GDPR.

It is also possible to apply props here to surface internet data, i.e., public data. In this case, data privacy isn’t at issue, but integrity remains important, i.e., assurance that Y=M(X) for public data X (or a combination of public and private data) remains valuable as evidence of the trustworthiness of Y.

#### Note (Remote execution):

In Example 2, Bob executes M locally. As M is executing on user devices, it is in effect publicly disclosed. An alternative is possible in which M is instead executed in a privacy-preserving cloud environment. In fact, props compose naturally with a range of privacy-preserving inference systems, such as Apple Intelligence Private Compute Cloud (PCC) [1].

In the case that M isn’t operated by the consumer of the inference—e.g., PrivaLoan in Example 2—a prop proof would include two components: (1) A proof of authenticity of X coupled with (2) Proof that Y=M(X). [Footnote 2: While Apple Intelligence PCC doesn’t currently generate proofs of the form Y=M(X), it does run on trusted execution environments with attestation capabilities. It could in principle therefore generate such proofs for consumption of inferences by parties other than Apple itself.]

### 2.3 Constraining adversarial inputs

Example 2 illustrates how props additionally offers a strategy for combating adversarial examples. Adversarial examples are maliciously generated inputs designed to cause models to produce erroneous outputs [12, 13, 27, 40]. PrivaLoan can trust Y because of its trustworthy provenance: Props authenticate the entire pipeline, from data source to output. As a result, an adversary has a limited ability to manipulate inputs.

Similarly, by constraining adversarial inputs, props can serve as a potential countermeasure to other forms of attack, such as model extraction [32] and recovery of sensitive training data [22, 31].

### 2.4 Data control, monetization, and decentralization

A user can choose to pre-process the data X obtained from a deep-web source for input to a prop. That is, she can choose to transmit some X^{\prime}=f(X), where a filter f excises or compresses data in X. The prop will then prove—using functionality already available in privacy-preserving oracle systems—that X^{\prime} is the result of applying f to an authentically sourced X. The filter f can redact data or compute over data in order, e.g., to compress or add noise it [11] to hedge against privacy failures should data leakage occur downstream.

In Example 1, for instance, rather than transmitting X to MediModels, Alice might wish to transmit a redacted EHR X^{\prime} from which she has excised her name and address. (Perhaps she’s concerned that these might leak from the trained model.) The prop specifies the filter f to MediModels. Thus MediModels learns that contact information is omitted from X^{\prime}. MediModels can, of course, choose to accept or reject an input X^{\prime} based on the filter f that generated it and might, for example, whitelist a set of pre-approved filters.

In short, users authorize the release of their data in props and can control this release in a granular way. Props could support a financial model in which an organization training an ML model compensates users for the data they furnish and filtering choices they apply.

Props could also support new, decentralized financial models in which users who provide training data receive a financial stake in a resulting ML model. It is in principle possible, for instance, to train and execute an ML model on a TEE-enabled blockchain such as Oasis Sapphire that ensures data privacy and can automatically bill for queries and distribute cryptocurrency tokens to community members who have earned a stake in the model [26].

#### Note (Ownership rights):

We don’t address the issue of data ownership here. In some cases, the right to make use of personal data as desired is clearly attributable to an individual user and supported by regulations such as Article 20 of GDPR [33], the right to data portability and, in the case of EHRs, the 21st Century Cures Act [9]. In other cases, as with photographs of individuals captured in private settings, legal restrictions, e.g., [17], or service agreements may limit a user’s sharing rights. It is the responsibility of an application developer to enforce appropriate data sharing policies. The authentication of data sources offered by props can be instrumental in this goal.

## 3 How Can Props Be Built?

Why do props not yet exist? How can we build them? Two critical building blocks are needed: secure data sourcing and pinned models. Both are practically realizable today using existing tools and techniques.

### 3.1 Secure data sourcing

Secure data sourcing ensures that the data entering a prop comes from a trustworthy source, such as a specific web service, in the expected context and with strong privacy protections. In Example 1 this means ensuring that X represents BigHospital serving Alice’s EHR. A practical enhancement allows Alice to apply redactions or other preprocessing before transmitting X. Alice’s data can then be input to the model-training environment—in encrypted form if the environment is privacy-preserving. Today, however, secure channels to web servers (TLS / HTTPS) do not digitally sign data [30]. That means that while users can access their own web data securely, there’s often no way to prove to someone else where the data came from. There are two ways to remedy this limitation of existing infrastructure.

#### Approach 1: Infrastructure Modification.

The first way to address the problem is to change the infrastructure, i.e., modify existing web services so that they sign data. JSON Web Tokens (JWTs) are an emerging standard for this purpose [14]. JWTs are gaining traction for certain forms of data, such as user credentials in OAuth 2.0 and OpenID Connect (OIDC). But most deep-web data isn’t served today in the form of JWTs.

#### Approach 2: Privacy-Preserving Oracles.

A second, infrastructure-independent approach involves privacy-preserving oracles [5]. These are tools developed for blockchain systems that allow secure data sourcing without modifying existing infrastructure. Privacy-preserving oracles come in two flavors. They can use trusted execution environments (TEEs) such as Intel SGX / TDX [8, 10, 20, 21] a technology that is increasingly supported in CPUs and even GPUs [23]. Town Crier [28, 41] was the first such oracle system. TEEs are flexible and powerful, but have long-recognized security limitations, such as repeatedly demonstrated vulnerability to side-channel attacks (e.g., in speculative execution) [4, 7, 16, 18, 34, 35, 36]. An alternative is to use a cryptographic alternative, often today called zkTLS [38] and first realized in the DECO system [42]. Both approaches enable a user to furnish deep-web data privately and with integrity to third parties in a prop as in our two examples. They work with any TLS-enabled web service. They also enable privacy protection as illustrated above: Data X can be pre-processed by a user and sent into a prop in encrypted form.

### 3.2 Pinned models

Secure data sourcing is generally sufficient for privacy-preserving model training, as in Example 1. But inference is another story. That requires the second building block for props, pinned models.

In Example 2, it isn’t enough for PrivaLoan, the consumer of the model’s output Y, to know that X is trustworthy. PrivaLoan also needs to know what model M was used for inference and the full execution environment E for M (hyperparameters, preprocessing, postprocessing, random seeds, etc.). If M was PrivaLoan’s own model, PrivaLoan will naturally want assurance that the inference Y was the output of M on X.

It may suffice for PrivaLoan’s purposes only to have model consistency, i.e., to know that X was input to a particular ML service, such as ChatGPT, without knowing exactly what E and M were. (ML services such as ChatGPT don’t reveal E and M and frequently change them, often silently.) Model consistency is compatible with model privacy, lack of disclosure of proprietary models and/or environments.

In some settings, however, the consumer of a prop's output Y will want an exact specification of E and M that is replicable. PrivaLoan might, for instance, want to be able to audit a prop used in its applications or test the prop's properties, such as susceptibility to adversarial inputs or hallucinations.

We define a pinned model broadly as one that includes a specification S=(E,M) along with a functionality that proves that Y is the result of applying S to some input X. The specification of S can be exact, but it could also be inexact—e.g., it could be the URL for an ML service. To support the full prop proof in privacy-preserving use cases like that in Example 2, the proof associated with a pinned model should not disclose X; it needs to be composable with a proof of authenticity for X.

### 3.3 Approaches for realizing pinned models

Executing a model (and environment) in a TEE is one practical way to realize pinned models. Recently rolled-out support for TEEs in NVIDIA GPUs [23] makes this approach especially viable. Another, complementary approach is to use a decentralized oracle network (DON) [5]. A committee of nodes in a DON could, for instance, each independently execute a model specification S on an input X and then reach consensus on the output Y. (Or they could each execute a different model specification, a form of ensemble learning [39].) Approaches such as zkML are also possible, but practical today only for small models [6].

## 4 Conclusion

Props represent a new approach for secure, privacy-preserving access to deep-web data sources in machine learning. By enabling authenticated, privacy-preserving data pipelines, they address critical bottlenecks in data availability and model reliability within ML. Props can ensure robust data privacy and integrity across an entire ML pipeline, from sourcing and processing to training and model execution. Props are also flexible: They can verify data authenticity and model consistency, for instance, even in standard ML applications that don’t require privacy. In short, by combining privacy-preserving oracle systems and pinned models, props establish a scalable pathway toward secure and reliable ML systems, unlocking the potential of deep-web data for ML capabilities.

In short, props create three significant opportunities for ML applications:

1. **Surfacing deep-web data**: Props enable deep-web data—which is vastly larger than surface-web data—to be used for ML training and inference with strong privacy and integrity assurance.
2. **Securing inference on sensitive data**: When used for inference, props create new models of data use. Service providers can obtain ML inferences over trustworthy models with private data. They can do so while avoiding the exposure to breaches and liability associated with direct access to sensitive data.
3. **Constraining adversarial inputs**: For applications that rely on deep-web data inputs, authenticating inputs limits opportunities for adversarial manipulation. As a result props can limit the impact of adversarial examples and other forms of adversarial input.

## Note on Props and Blockchain Technologies

It’s not a coincidence that most of the technical tools needed for props saw some of their earliest production use in blockchain systems. High-assurance data delivery and application execution are especially prized in smart-contract-based blockchains, where adversaries can exploit even small vulnerabilities for quick monetary gain. Also, blockchain systems by design create a tension between transparency and privacy. Blockchains are transparent, but financial transactions usually involve sensitive data. Systems that ensure both data authenticity and privacy—such as privacy-preserving oracle systems—have sprung up to resolve this tension.

Props are not just realizable using blockchain technologies but can also be useful for blockchain technologies. This is particularly true of props for inference, as in Example 2. The privacy-preserving, authenticated nature of outputs makes them suitable for consumption by smart contracts.

## Acknowledgments

Thanks to James Austgen, Lorenz Breidenbach, and Mahimna Kelkar for their helpful comments on this work. Thanks especially to Andrés Fábrega for pointing out uses for constraining adversarial inputs beyond adversarial examples.

## References

- [1] Apple Security Engineering and Architecture. Private cloud compute: A new era of confidentiality and security in cloud services, 2023. Accessed: 2024-10-23.
- [2] Barth, A., Datta, A., Mitchell, J. C., and Nissenbaum, H. Privacy and contextual integrity: Framework and applications. In 2006 IEEE Symposium on Security and Privacy (S&P’06) (2006).
- [3] Bergman, M. K. White paper: the deep web: surfacing hidden value. Journal of electronic publishing 7, 1 (2001).
- [4] Borrello, P., Kogler, A., Schwarzl, M., Lipp, M., Gruss, D., and Schwarz, M. AEPIC leak: Architecturally leaking uninitialized data from the microarchitecture. In 31st USENIX Security Symposium (USENIX Security 22) (2022), pp. 3917–3934.
- [5] Breidenbach, L., Cachin, C., Chan, B., Coventry, A., Ellis, S., Juels, A., Koushanfar, F., Miller, A., Magauran, B., Moroz, D., et al. Chainlink 2.0: Next steps in the evolution of decentralized oracle networks, 2021.
- [6] Chen, B.-J., Waiwitlikhit, S., Stoica, I., and Kang, D. Zkml: An optimizing system for ml inference in zero-knowledge proofs. In Proceedings of the Nineteenth European Conference on Computer Systems (2024), pp. 560–574.
- [7] Chen, G., Chen, S., Xiao, Y., Zhang, Y., Lin, Z., and Lai, T. H. Sgxpectre: Stealing intel secrets from sgx enclaves via speculative execution. In 2019 IEEE European Symposium on Security and Privacy (EuroS&P) (2019), IEEE, pp. 142–157.
- [8] Cheng, P.-C., Ozga, W., Valdez, E., Ahmed, S., Gu, Z., Jamjoom, H., Franke, H., and Bottomley, J. Intel tdx demystified: A top-down approach. ACM Computing Surveys 56, 9 (2024), 1–33.
- [9] Congress, U. 21st century cures act - electronic health record data portability. https://www.congress.gov/bill/114th-congress/house-bill/34, 2016. Accessed: 2024-10-23.
- [10] Costan, V. Intel sgx explained. IACR Cryptol, EPrint Arch (2016).
- [11] El Ouadrhiri, A., and Abdelhadi, A. Differential privacy for deep and federated learning: A survey. IEEE access 10 (2022), 22359–22380.
- [12] Goodfellow, I. J. Explaining and harnessing adversarial examples. arXiv preprint arXiv:1412.6572 (2014).
- [13] Ilyas, A., Santurkar, S., Tsipras, D., Engstrom, L., Tran, B., and Madry, A. Adversarial examples are not bugs, they are features. Advances in neural information processing systems 32 (2019).
- [14] Json web tokens - jwt.io. https://jwt.io/. Accessed: 2024-10-22.
- [15] Kairouz, P., et al. Advances and open problems in federated learning. Foundations and trends® in machine learning 14, 1–2 (2021), 1–210.
- [16] Kocher, P., Horn, J., Fogh, A., Genkin, D., Gruss, D., Haas, W., Hamburg, M., Lipp, M., Mangard, S., Prescher, T., et al. Spectre attacks: Exploiting speculative execution. Communications of the ACM 63, 7 (2020), 93–101.
- [17] Legislature, C. California consumer privacy act (ccpa) - sharing of personal information. https://oag.ca.gov/privacy/ccpa, 2018. Accessed: 2024-10-23.
- [18] Lipp, M., Schwarz, M., Gruss, D., Prescher, T., Haas, W., Mangard, S., Kocher, P., Genkin, D., Yarom, Y., and Hamburg, M. Meltdown. arXiv preprint arXiv:1801.01207 (2018).
- [19] Longpre, S., Mahari, R., Lee, A., Lund, C., Oderinwale, H., Brannon, W., Saxena, N., Obeng-Marnu, N., South, T., Hunter, C., et al. Consent in crisis: The rapid decline of the AI data commons. arXiv preprint arXiv:2407.14933 (2024).
- [20] McKeen, F., Alexandrovich, I., Anati, I., Caspi, D., Johnson, S., Leslie-Hurd, R., and Rozas, C. Intel® software guard extensions (intel® sgx) support for dynamic memory management inside an enclave. In Proceedings of the Hardware and Architectural Support for Security and Privacy 2016 (2016), pp. 1–9.
- [21] McKeen, F., Alexandrovich, I., Berenzon, A., Rozas, C. V., Shafi, H., Shanbhogue, V., and Savagaonkar, U. R. Innovative instructions and software model for isolated execution. Hasp@ isca 10, 1 (2013).
- [22] Nasr, M., Carlini, N., Hayase, J., Jagielski, M., Cooper, A. F., Ippolito, D., Choquette-Choo, C. A., Wallace, E., Tramèr, F., and Lee, K. Scalable extraction of training data from (production) language models. arXiv preprint arXiv:2311.17035 (2023).
- [23] Nertney, R. Announcing confidential computing general access on nvidia h100 tensor core gpus. NVIDIA.Developer (25 Apr. 2024).
- [24] Nikolenko, S. I. Synthetic data for deep learning, vol. 174. Springer, 2021.
- [25] Nissenbaum, H. F. Privacy in Context: Technology, Policy, and the Integrity of Social Life. Stanford Law Books, 2010.
- [26] Oasis Protocol Foundation. Oasis powers responsible AI with smart privacy, 2024. Accessed: 2024-10-22.
- [27] Papernot, N., McDaniel, P., Jha, S., Fredrikson, M., Celik, Z. B., and Swami, A. The limitations of deep learning in adversarial settings. In 2016 IEEE European symposium on security and privacy (EuroS&P) (2016), IEEE, pp. 372–387.
- [28] Pollock, D. Cornell’s Town Crier acquired by Chainlink to expand decentralized oracle network. Forbes (Nov 1, 2018).
- [29] Rai, S., Singh, K., and Varma, A. K. A bibliometric analysis of deep web research during 1997-2019. DESIDOC Journal of Library & Information Technology 40, 2 (2020).
- [30] Rescorla, E. The Transport Layer Security (TLS) Protocol Version 1.3. RFC 8446, 2018. Accessed: 2024-10-23.
- [31] Song, C., Ristenpart, T., and Shmatikov, V. Machine learning models that remember too much. In Proceedings of the 2017 ACM SIGSAC Conference on computer and communications security (2017), pp. 587–601.
- [32] Tramèr, F., Zhang, F., Juels, A., Reiter, M. K., and Ristenpart, T. Stealing machine learning models via prediction apis. In 25th USENIX security symposium (USENIX Security 16) (2016), pp. 601–618.
- [33] Union, E. General data protection regulation (gdpr) - article 20: Right to data portability. https://gdpr.eu/article-20-right-to-data-portability/, 2016. Accessed: 2024-10-23.
- [34] Van Bulck, J., Minkin, M., Weisse, O., Genkin, D., Kasikci, B., Piessens, F., Silberstein, M., Wenisch, T. F., Yarom, Y., and Strackx, R. Foreshadow: Extracting the keys to the intel \{ SGX \} kingdom with transient out-of-order execution. In 27th USENIX Security Symposium (USENIX Security 18) (2018), pp. 991–1008.
- [35] van Schaik, S., Kwong, A., Genkin, D., and Yarom, Y. SGAxe: How SGX fails in practice, 2020.
- [36] Van Schaik, S., Seto, A., Yurek, T., Batori, A., AlBassam, B., Genkin, D., Miller, A., Ronen, E., Yarom, Y., and Garman, C. Sok: Sgx. fail: How stuff gets exposed. In 2024 IEEE Symposium on Security and Privacy (SP) (2024), IEEE, pp. 4143–4162.
- [37] Villalobos, P., Ho, A., Sevilla, J., Besiroglu, T., Heim, L., and Hobbhahn, M. Position: Will we run out of data? limits of llm scaling based on human-generated data. In Forty-first International Conference on Machine Learning.
- [38] Wetzel, B. Tls oracles: Liberating private web data with cryptography. https://bwetzel.medium.com/tls-oracles-liberating-private-web-data-with-cryptography-e66e5fad7c34, 2024. Accessed: 2024-10-22.
- [39] Wikipedia contributors. Ensemble learning. https://en.wikipedia.org/wiki/Ensemble_learning, 2024. Accessed: 2024-10-22.
- [40] Yuan, X., He, P., Zhu, Q., and Li, X. Adversarial examples: Attacks and defenses for deep learning. IEEE transactions on neural networks and learning systems 30, 9 (2019), 2805–2824.
- [41] Zhang, F., Cecchetti, E., Croman, K., Juels, A., and Shi, E. Town crier: An authenticated data feed for smart contracts. In Proceedings of the 2016 ACM SIGSAC conference on computer and communications security (2016), pp. 270–282.
- [42] Zhang, F., Maram, D., Malvai, H., Goldfeder, S., and Juels, A. Deco: Liberating web data using decentralized oracles for tls. In Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security (2020), pp. 1919–1938.
