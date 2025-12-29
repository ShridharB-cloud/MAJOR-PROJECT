import SignUpBlock from './SignUpBlock';

interface SignUpProps {
    onNavigate: (view: 'login') => void;
}

const SignUp = ({ onNavigate }: SignUpProps) => {
    return (
        <div className="min-h-[calc(100vh-80px)] grid place-items-center p-4">
            <SignUpBlock onNavigate={onNavigate} />
        </div>
    );
};

export default SignUp;
