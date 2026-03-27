# Ollama needs to be present

need to pull the following

```bash
ollama pull qwen3.5:9b
ollama pull qwen3.5:397b-cloud
ollama pull glm-5:cloud
```

then run

```bash
# grant exec permissions
chmod +x ./create-local-auditors.sh
chmod +x ./delete-local-auditors.sh

# Create local auditors
./create-local-auditors.sh

# Delete local auditors
./delete-local-auditors.sh
```

After successful creation of skilled auditors and the supervisor you will have the following models:

- `qwen-junior-auditor` --> `qwen3.5:9b`
- `qwen-senior-auditor` --> `qwen3.5:397b-cloud`
- `glm-senior-auditor` --> `glm-5:cloud`
- `glm-supervisor` --> `glm-5:cloud`
