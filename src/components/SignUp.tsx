import SignUpBlock from './SignUpBlock';
import { BeamsBackground } from './ui/beams-background';

interface SignUpProps {
    onNavigate: (view: 'login') => void;
}

const SignUp = ({ onNavigate }: SignUpProps) => {
    return (
        <BeamsBackground intensity="medium" className="min-h-[calc(100vh-80px)]">
            <div className="min-h-[calc(100vh-80px)] grid place-items-center p-4">
                <SignUpBlock onNavigate={onNavigate} />
            </div>
        </BeamsBackground>
    );
};

export default SignUp;
