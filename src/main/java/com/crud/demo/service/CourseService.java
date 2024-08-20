package com.crud.demo.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.crud.demo.entity.Course;
import com.crud.demo.repository.CourseRepository;

@Service
public class CourseService {
    @Autowired
    CourseRepository repository;

    // Fetch all courses
    public List<Course> findAllCourses() {
        return (List<Course>) repository.findAll();
    }

    // Fetch a course by ID
    public Course findCourseById(int id) {
        Optional<Course> result = repository.findById(id);
        return result.orElseGet(Course::new); // Return a new Course object if not found
    }

    // Add a new course
    public Course addCourse(Course course) {
        return repository.save(course); // Saves the course with ID, name, tech, and noOfDays
    }

    // Update an existing course
    public Course updateCourse(Course course) {
        Optional<Course> result = repository.findById(course.getId());
        if (result.isPresent()) {
            Course existing = result.get();
            existing.setTech(course.getTech());
            existing.setName(course.getName());
            existing.setNoOfDays(course.getNoOfDays());
            return repository.save(existing); // Updates the existing course
        }
        return null; // Handle the case where the course is not found
    }

    // Delete a course by ID
    public void deleteById(int id) {
        repository.deleteById(id);
    }
}
