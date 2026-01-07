import SignInBlock from './SignInBlock';
import { BeamsBackground } from './ui/beams-background';

interface LoginProps {
    onNavigate: (view: 'signup' | 'home' | 'scanner') => void;
    onLogin: () => void;
}

const Login = ({ onNavigate, onLogin }: LoginProps) => {
    return (
        <BeamsBackground intensity="medium" className="min-h-[calc(100vh-80px)]">
            <div className="min-h-[calc(100vh-80px)] grid place-items-center p-4">
                <SignInBlock onNavigate={onNavigate} onLogin={onLogin} />
            </div>
        </BeamsBackground>
    );
};

export default Login;
