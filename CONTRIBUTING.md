# Contributing to ThreatScope

Thank you for your interest in contributing to ThreatScope! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites

- Python 3.11 or higher
- PostgreSQL 14+
- Redis (optional, for caching)
- Git

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/threatscope.git
   cd threatscope
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Setup Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Initialize Database**
   ```bash
   python scripts/setup_db.py
   ```

## 📝 Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b bugfix/issue-number
```

### 2. Make Changes

- Follow the existing code structure
- Write clean, readable code
- Add docstrings to functions and classes
- Update documentation if needed

### 3. Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test file
pytest tests/test_graph.py -v
```

### 4. Code Quality Checks

```bash
# Format code with Black
black src tests

# Sort imports
isort src tests

# Lint with flake8
flake8 src tests

# Type check
mypy src
```

### 5. Commit Changes

Follow conventional commit messages:

```bash
git commit -m "feat: add new threat collector for XYZ"
git commit -m "fix: resolve graph visualization bug"
git commit -m "docs: update API documentation"
```

**Commit Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

### 6. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## 🏗️ Project Structure

```
src/
├── core/          # Core data structures
├── ai/            # AI/OpenAI integration
├── api/           # FastAPI REST API
├── collectors/    # Threat feed collectors
├── database/      # Database models
├── dashboard/     # Streamlit dashboard
└── utils/         # Utility functions
```

## 📋 Contribution Guidelines

### Code Style

- Follow PEP 8 style guide
- Use type hints where appropriate
- Maximum line length: 100 characters
- Use meaningful variable names
- Add comments for complex logic

### Documentation

- Add docstrings to all public functions/classes
- Update README.md if adding new features
- Include examples in docstrings
- Keep documentation up to date

### Testing

- Write tests for new features
- Maintain test coverage above 80%
- Use pytest fixtures for common setup
- Mock external API calls in tests

### Security

- Never commit API keys or secrets
- Use environment variables for sensitive data
- Validate all user inputs
- Follow OWASP security guidelines

## 🐛 Reporting Bugs

### Before Submitting

- Check if the bug is already reported
- Ensure you're using the latest version
- Try to reproduce the bug

### Bug Report Template

```markdown
**Description:**
Clear description of the bug

**Steps to Reproduce:**
1. Step 1
2. Step 2
3. ...

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.11.2]
- ThreatScope Version: [e.g., 1.0.0]

**Additional Context:**
Any other relevant information
```

## ✨ Feature Requests

### Feature Request Template

```markdown
**Feature Description:**
Clear description of the proposed feature

**Use Case:**
Why is this feature needed?

**Proposed Solution:**
How should this be implemented?

**Alternatives Considered:**
Other approaches you've thought about

**Additional Context:**
Any other relevant information
```

## 🔄 Pull Request Process

1. **Update Documentation**: Ensure README and docs are updated
2. **Add Tests**: Include tests for new features
3. **Pass CI/CD**: All checks must pass
4. **Review**: Wait for code review
5. **Address Feedback**: Make requested changes
6. **Merge**: Maintainers will merge when ready

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] No merge conflicts
- [ ] CI/CD checks pass

## 🏆 Recognition

Contributors will be added to:
- GitHub contributors list
- Project README credits
- Release notes

## 📞 Getting Help

- **Discord**: [Join our community]
- **Issues**: GitHub issue tracker
- **Email**: team@threatscope.dev

## 📜 Code of Conduct

### Our Standards

- Be respectful and inclusive
- Accept constructive criticism
- Focus on what's best for the community
- Show empathy towards others

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Personal or political attacks
- Publishing private information

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to ThreatScope! 🛡️