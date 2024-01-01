pub fn FillStructureFromMemory<T>(dest: &mut T,src: *const c_void,prochandle: *mut c_void,) -> usize {
    unsafe {
        let bytestoread: usize = std::mem::size_of::<T>();
        ////println!("size of structure is {}",bytestoread);
        let mut buffer: Vec<u8> = vec![0; bytestoread];
        let mut byteswritten = 0;
        let res = ReadProcessMemory(
            prochandle,
            src,
            buffer.as_mut_ptr() as *mut c_void,
            bytestoread,
            &mut byteswritten,
        );
        ////println!("array being filled: {:x?}",&buffer);
        FillStructureFromArray(dest, &buffer);

        return byteswritten;
    }
}


pub fn FillStructureFromArray<T, U>(base: &mut T, arr: &[U]) -> usize {

    unsafe {
        //println!("{}",std::mem::size_of::<T>());
        //println!("{}",std::mem::size_of_val(arr));
        /*if std::mem::size_of::<T>() != std::mem::size_of_val(arr) {
            println!("{}", std::mem::size_of::<T>());
            println!("{}", std::mem::size_of_val(arr));
            panic!("sizes are not equal to copy");
        }*/

        let mut handle = GetCurrentProcess();
        let mut byteswritten = 0;
        let res = WriteProcessMemory(
            handle,
            base as *mut _ as *mut c_void,
            arr as *const _ as *const c_void,
            std::mem::size_of::<T>(),
            &mut byteswritten,
        );

        return byteswritten;
    }
}
