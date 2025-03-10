pub use crate::error::{ExitError, ExitReason};

macro_rules! try_or_fail {
    ( $e:expr ) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Control::Exit(e.into()),
        }
    };
}

macro_rules! inspect {
    ($handler:ident, $inspect_fn:ident) => {
        if H::INSPECT {
            $handler.inspect().$inspect_fn();
        }
    };
    ($handler:ident, $inspect_fn:ident, $($args:expr),*) => {
        if H::INSPECT {
            $handler.inspect().$inspect_fn( $($args),* );
        }
    };
}

macro_rules! check {
    ($expresion:expr) => {
        if !$expresion {
            return Control::Exit(ExitReason::Error(ExitError::OpcodeNotFound));
        }
    };
}

macro_rules! gas {
    ($machine:expr, $gas:expr) => {
        if crate::USE_GAS {
            if !$machine.gas.record_cost(($gas)) {
                return Control::Exit(ExitReason::Error(ExitError::OutOfGas));
            }
        }
    };
}

macro_rules! refund {
    ($machine:expr, $gas:expr) => {{
        if crate::USE_GAS {
            $machine.gas.gas_refund($gas);
        }
    }};
}

macro_rules! gas_or_fail {
    ($machine:expr, $gas:expr) => {
        if crate::USE_GAS {
            match $gas {
                Some(gas_used) => gas!($machine, gas_used),
                None => return Control::Exit(ExitReason::Error(ExitError::OutOfGas)),
            }
        }
    };
}

macro_rules! memory_resize {
    ($machine:expr, $start:expr, $len:expr) => {{
        let new_gas_memory = try_or_fail!($machine.memory.resize_offset($start, $len));
        if crate::USE_GAS {
            if !$machine.gas.record_memory(new_gas_memory) {
                return Control::Exit(ExitReason::Error(ExitError::OutOfGas));
            }
        }
    }};
}

macro_rules! pop {
    ( $machine:expr, $x1:ident) => {
        if $machine.stack.len() < 1 {
            return Control::Exit(ExitError::StackUnderflow.into());
        }
        let $x1 = unsafe { $machine.stack.pop_unsafe() };
    };
    ( $machine:expr, $x1:ident, $x2:ident) => {
        if $machine.stack.len() < 2 {
            return Control::Exit(ExitError::StackUnderflow.into());
        }
        let $x1 = unsafe { $machine.stack.pop_unsafe() };
        let $x2 = unsafe { $machine.stack.pop_unsafe() };
    };
}

macro_rules! pop_u256 {
    ( $machine:expr, $x1:ident) => {
        if $machine.stack.len() < 1 {
            return Control::Exit(ExitError::StackUnderflow.into());
        }
        let $x1 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
    };
    ( $machine:expr, $x1:ident, $x2:ident) => {
        if $machine.stack.len() < 2 {
            return Control::Exit(ExitError::StackUnderflow.into());
        }
        let $x1 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
        let $x2 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
    };
    ( $machine:expr, $x1:ident, $x2:ident, $x3:ident) => {
        if $machine.stack.len() < 3 {
            return Control::Exit(ExitError::StackUnderflow.into());
        }
        let $x1 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
        let $x2 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
        let $x3 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
    };

    ( $machine:expr, $x1:ident, $x2:ident, $x3:ident, $x4:ident) => {
        if $machine.stack.len() < 4 {
            return Control::Exit(ExitError::StackUnderflow.into());
        }
        let $x1 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
        let $x2 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
        let $x3 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
        let $x4 = unsafe { U256::from_big_endian(&$machine.stack.pop_unsafe()[..]) };
    };
}

macro_rules! push {
	( $machine:expr, $( $x:expr ),* ) => (
		$(
			match $machine.stack.push($x) {
				Ok(()) => (),
				Err(e) => return Control::Exit(e.into()),
			}
		)*
	)
}

macro_rules! push_u256 {
	( $machine:expr, $( $x:expr ),* ) => (
		$(
			let mut value = H256::default();
			$x.to_big_endian(&mut value[..]);
			match $machine.stack.push(value) {
				Ok(()) => (),
				Err(e) => return Control::Exit(e.into()),
			}
		)*
	)
}

macro_rules! op1_u256_fn {
    ( $machine:expr, $op:path, $gas:expr ) => {{
        gas!($machine, $gas);
        pop_u256!($machine, op1);
        let ret = $op(op1);
        push_u256!($machine, ret);

        Control::Continue
    }};
}

macro_rules! op2_u256_bool_ref {
    ( $machine:expr, $op:ident, $gas:expr ) => {{
        gas!($machine, $gas);
        pop_u256!($machine, op1, op2);
        let ret = op1.$op(&op2);
        push_u256!($machine, if ret { U256::one() } else { U256::zero() });

        Control::Continue
    }};
}

macro_rules! op2_u256 {
    ( $machine:expr, $op:ident, $gas:expr ) => {{
        gas!($machine, $gas);
        pop_u256!($machine, op1, op2);
        let ret = op1.$op(op2);
        push_u256!($machine, ret);

        Control::Continue
    }};
}

macro_rules! op2_u256_tuple {
    ( $machine:expr, $op:ident, $gas:expr ) => {{
        gas!($machine, $gas);

        pop_u256!($machine, op1, op2);
        let (ret, ..) = op1.$op(op2);
        push_u256!($machine, ret);

        Control::Continue
    }};
}

macro_rules! op2_u256_fn {
    ( $machine:expr, $op:path, $gas:expr  ) => {{
        gas!($machine, $gas);

        pop_u256!($machine, op1, op2);
        let ret = $op(op1, op2);
        push_u256!($machine, ret);

        Control::Continue
    }};
    ( $machine:expr, $op:path, $gas:expr, $enabled:expr) => {{
        check!(($enabled));
        op2_u256_fn!($machine, $op, $gas)
    }};
}

macro_rules! op3_u256_fn {
    ( $machine:expr, $op:path, $gas:expr  ) => {{
        gas!($machine, $gas);

        pop_u256!($machine, op1, op2, op3);
        let ret = $op(op1, op2, op3);
        push_u256!($machine, ret);

        Control::Continue
    }};
    ( $machine:expr, $op:path, $gas:expr, $spec:ident :: $enabled:ident) => {{
        check!($spec::$enabled);
        op3_u256_fn!($machine, $op, $gas)
    }};
}

macro_rules! as_usize_or_fail {
    ( $v:expr ) => {{
        if $v > U256::from(usize::MAX) {
            return Control::Exit(ExitFatal::NotSupported.into());
        }

        $v.as_usize()
    }};

    ( $v:expr, $reason:expr ) => {{
        if $v > U256::from(usize::MAX) {
            return Control::Exit($reason.into());
        }

        $v.as_usize()
    }};
}
