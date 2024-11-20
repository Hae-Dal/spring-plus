package org.example.expert.domain.todo.service;

import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.example.expert.client.WeatherClient;
import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.example.expert.domain.todo.dto.request.TodoSaveRequest;
import org.example.expert.domain.todo.dto.response.TodoResponse;
import org.example.expert.domain.todo.dto.response.TodoSaveResponse;
import org.example.expert.domain.todo.entity.QTodo;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.todo.repository.TodoRepository;
import org.example.expert.domain.user.dto.response.UserResponse;
import org.example.expert.domain.user.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TodoService {

    private final TodoRepository todoRepository;
    private final WeatherClient weatherClient;
    private final JPAQueryFactory queryFactory;  // QueryDSL의 JPAQueryFactory 주입

    @Transactional
    public TodoSaveResponse saveTodo(AuthUser authUser, TodoSaveRequest todoSaveRequest) {
        User user = User.fromAuthUser(authUser);

        String weather = weatherClient.getTodayWeather();

        Todo newTodo = new Todo(
                todoSaveRequest.getTitle(),
                todoSaveRequest.getContents(),
                weather,
                user
        );
        Todo savedTodo = todoRepository.save(newTodo);

        return new TodoSaveResponse(
                savedTodo.getId(),
                savedTodo.getTitle(),
                savedTodo.getContents(),
                weather,
                new UserResponse(user.getId(), user.getEmail(), user.getNickname())
        );
    }

    public Page<TodoResponse> getTodos(int page, int size, String weather) {
        Pageable pageable = PageRequest.of(page - 1, size);

        QTodo qTodo = QTodo.todo;

        List<Todo> todos = queryFactory.selectFrom(qTodo)
                .leftJoin(qTodo.user).fetchJoin()  // N+1 문제를 방지하기 위해 fetchJoin 사용
                .where(weather == null ? null : qTodo.weather.eq(weather))
                .orderBy(qTodo.modifiedAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        long total = queryFactory.selectFrom(qTodo)
                .where(weather == null ? null : qTodo.weather.eq(weather))
                .fetchCount();

        List<TodoResponse> todoResponses = todos.stream().map(todo -> new TodoResponse(
                todo.getId(),
                todo.getTitle(),
                todo.getContents(),
                todo.getWeather(),
                new UserResponse(todo.getUser().getId(), todo.getUser().getEmail(), todo.getUser().getNickname()),
                todo.getCreatedAt(),
                todo.getModifiedAt()
        )).toList();

        return new PageImpl<>(todoResponses, pageable, total);
    }

    public TodoResponse getTodo(long todoId) {
        QTodo qTodo = QTodo.todo;

        Todo todo = queryFactory.selectFrom(qTodo)
                .leftJoin(qTodo.user).fetchJoin()  // N+1 문제를 방지하기 위해 fetchJoin 사용
                .where(qTodo.id.eq(todoId))
                .fetchOne();

        if (todo == null) {
            throw new InvalidRequestException("Todo not found");
        }

        User user = todo.getUser();

        return new TodoResponse(
                todo.getId(),
                todo.getTitle(),
                todo.getContents(),
                todo.getWeather(),
                new UserResponse(user.getId(), user.getEmail(), user.getNickname()),
                todo.getCreatedAt(),
                todo.getModifiedAt()
        );
    }
}
