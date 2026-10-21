import os


class SecurityBehaviorChecker:
    def suspicious_calls(self):
        suspicious = []
        syscalls = ["os.system", "eval", "exec"]
        try:
            with open(__file__, 'r') as f:
                content = f.read()
                for call in syscalls:
                    if call in content:
                        suspicious.append(call)
        except:
            pass
        return suspicious
