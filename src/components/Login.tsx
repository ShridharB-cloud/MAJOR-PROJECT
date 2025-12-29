import SignInBlock from './SignInBlock';
import { BeamsBackground } from './ui/beams-background';

interface LoginProps {
    onNavigate: (view: 'signup') => void;
}

const Login = ({ onNavigate }: LoginProps) => {
    return (
        <BeamsBackground intensity="medium" className="min-h-[calc(100vh-80px)]">
            <div className="min-h-[calc(100vh-80px)] grid place-items-center p-4">
                <SignInBlock onNavigate={onNavigate} />
            </div>
        </BeamsBackground>
    );
};

export default Login;
